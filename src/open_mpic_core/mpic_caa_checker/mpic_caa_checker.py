import re
import time
from typing import Final, Optional
import dns.resolver
import dns.asyncresolver
from dns.name import Name
from dns.rrset import RRset

from open_mpic_core import CaaCheckRequest, CaaCheckResponse, CaaCheckResponseDetails
from open_mpic_core import MpicValidationError, ErrorMessages
from open_mpic_core import DomainEncoder
from open_mpic_core import get_logger
from open_mpic_core import CertificateType

ISSUE_TAG: Final[str] = "issue"
ISSUEWILD_TAG: Final[str] = "issuewild"
ISSUEMAIL_TAG: Final[str] = "issuemail"
IODEF_TAG: Final[str] = "iodef"
# to accommodate email and phone based DCV that gets contact info from CAA records
CONTACTEMAIL_TAG: Final[str] = "contactemail"
CONTACTPHONE_TAG: Final[str] = "contactphone"

logger = get_logger(__name__)


class MpicCaaLookupException(Exception):  # This is a python exception type used for raise statements.
    pass


class MpicCaaChecker:
    def __init__(self, default_caa_domain_list: list[str], log_level: int = None):
        self.default_caa_domain_list = default_caa_domain_list

        self.logger = logger.getChild(self.__class__.__name__)
        if log_level is not None:
            self.logger.setLevel(log_level)

    async def find_caa_records_and_domain(self, caa_request) -> tuple[RRset, Name]:
        rrset = None
        domain = dns.name.from_text(caa_request.domain_or_ip_target)

        while domain != dns.name.root:
            try:
                lookup = await dns.asyncresolver.resolve(domain, dns.rdatatype.CAA)
                rrset = lookup.rrset
                break
            except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
                domain = domain.parent()
            except Exception as e:
                self.logger.error(f"Exception during CAA lookup: {e}. Trace identifier: {caa_request.trace_identifier}")
                raise MpicCaaLookupException(f"{e}") from e

        return rrset, domain

    async def check_caa(self, caa_request: CaaCheckRequest) -> CaaCheckResponse:
        # noinspection PyUnresolvedReferences
        self.logger.trace(f"Checking CAA for {caa_request.domain_or_ip_target}")

        # Assume the default system configured validation targets and override if sent in the API call.
        caa_domains = self.default_caa_domain_list
        is_wc_domain = False
        certificate_type = CertificateType.TLS_SERVER
        if caa_request.caa_check_parameters:
            certificate_type = caa_request.caa_check_parameters.certificate_type   # defaults to TLS_SERVER
            if caa_request.caa_check_parameters.caa_domains:
                caa_domains = caa_request.caa_check_parameters.caa_domains

            # Use the domain name to determine if it is a wildcard domain
            # check if domain or ip target has an asterisk as its lowest (first) label (e.g. *.example.com)
            if caa_request.domain_or_ip_target.startswith("*."):
                is_wc_domain = True

        caa_lookup_error = False
        caa_found = False
        domain = None
        rrset = None

        caa_check_response = CaaCheckResponse(
            check_completed=False,
            check_passed=False,
            errors=None,
            details=CaaCheckResponseDetails(caa_record_present=None),
            timestamp_ns=None,
        )

        try:
            # encode domain if needed
            caa_request.domain_or_ip_target = DomainEncoder.prepare_target_for_lookup(caa_request.domain_or_ip_target)

            # noinspection PyUnresolvedReferences
            async with self.logger.trace_timing(f"CAA lookup for target {caa_request.domain_or_ip_target}"):
                rrset, domain = await self.find_caa_records_and_domain(caa_request)
            caa_found = rrset is not None
        except (MpicCaaLookupException, ValueError) as e:
            caa_lookup_error = True
            error_message = f"Error during CAA lookup: {e}"
            caa_check_response.errors = [MpicValidationError.create(ErrorMessages.CAA_LOOKUP_ERROR, error_message)]
            caa_check_response.details.found_at = None
            caa_check_response.details.records_seen = None

        if caa_lookup_error:
            pass
        elif not caa_found:  # if domain has no CAA records: valid for issuance
            caa_check_response.check_completed = True
            caa_check_response.check_passed = True
            caa_check_response.details.caa_record_present = False
            caa_check_response.details.found_at = None
            caa_check_response.details.records_seen = None
        else:
            caa_check_response.check_completed = True
            valid_for_issuance = MpicCaaChecker.is_valid_for_issuance(
                caa_domains, certificate_type, is_wc_domain, rrset
            )
            caa_check_response.check_passed = valid_for_issuance
            caa_check_response.details.caa_record_present = True
            caa_check_response.details.found_at = domain.to_text(omit_final_dot=True)
            caa_check_response.details.records_seen = [record_data.to_text() for record_data in rrset]
        caa_check_response.timestamp_ns = time.time_ns()

        # noinspection PyUnresolvedReferences
        self.logger.trace(f"Completed CAA for {caa_request.domain_or_ip_target}")
        return caa_check_response

    @staticmethod
    def is_valid_for_issuance(caa_domains, certificate_type: CertificateType, is_wc_domain, rrset) -> bool:
        issue_tags = []
        issue_wild_tags = []
        issue_mail_tags = []
        has_unknown_critical_flags = False

        # Note: a record with critical flag and 'issue' tag will be considered valid for issuance
        for resource_record in rrset:
            tag = resource_record.tag.decode("utf-8")
            tag_lower = tag.lower()
            val = resource_record.value.decode("utf-8")
            if tag_lower == ISSUE_TAG:
                issue_tags.append(val)
            elif tag_lower == ISSUEWILD_TAG:
                issue_wild_tags.append(val)
            elif tag_lower == ISSUEMAIL_TAG:
                issue_mail_tags.append(val)
            elif (
                not (tag_lower in [CONTACTEMAIL_TAG, CONTACTPHONE_TAG, IODEF_TAG])
                and resource_record.flags & 0b10000000
            ):  # bitwise-and to check if flags are 128 (the critical flag)
                has_unknown_critical_flags = True

        if has_unknown_critical_flags:
            valid_for_issuance = False
        elif certificate_type == CertificateType.S_MIME:
            if len(issue_mail_tags) > 0:
                valid_for_issuance = MpicCaaChecker.do_caa_values_permit_issuance(issue_mail_tags, caa_domains)
            else:
                # No issue mail tags
                valid_for_issuance = True
        elif certificate_type == CertificateType.TLS_SERVER:
            if is_wc_domain and len(issue_wild_tags) > 0:
                valid_for_issuance = MpicCaaChecker.do_caa_values_permit_issuance(issue_wild_tags, caa_domains)
            elif len(issue_tags) > 0:
                valid_for_issuance = MpicCaaChecker.do_caa_values_permit_issuance(issue_tags, caa_domains)
            else:
                # We had no unknown critical tags, and we found no issue tags. Issuance can proceed.
                valid_for_issuance = True
        else:
            # This is the case of an unimplemented certificate type. We cannot determine if issuance is valid or not. This case should never be hit as all values of the certificate type enum should be tested for in the above logic.
            valid_for_issuance = False
        return valid_for_issuance

    @staticmethod
    def do_caa_values_permit_issuance(value_list: list, caa_domains):
        issuance_permitted = False
        for value in value_list:
            try:
                # we don't do anything with the parameters yet, but we will eventually
                domain, parameters = MpicCaaChecker.extract_domain_and_parameters_from_caa_value(value)
                if domain.lower() in caa_domains:  # if the value is in the list of valid CAA domains
                    issuance_permitted = True
                    break
            except ValueError as ve:
                logger.warning(f"Error parsing CAA value: {ve}")

        return issuance_permitted  # if nothing matched, we cannot issue

    @staticmethod
    def extract_domain_and_parameters_from_caa_value(caa_value: str) -> tuple[str, Optional[dict[str, str]]]:
        # Split on semicolons since they're prohibited in parameter tag/value
        parameters = {}
        if ";" in caa_value:
            parts = caa_value.split(";")
            # Extract and trim issuer domain name
            issuer_domain_name = parts[0].strip()
            param_list = parts[1:]

            if not (len(param_list) == 1 and param_list[0].strip() == ""):  # if actual parameters follow the semicolon
                for parameter in param_list:
                    # Split on first equals sign (allowed in value but not tag)
                    tag_and_value = parameter.split("=", 1)
                    if len(tag_and_value) != 2:
                        raise ValueError(f"CAA parameter not formatted as tag=value: {parameter!r}")

                    tag = tag_and_value[0].strip()
                    value = tag_and_value[1].strip()

                    # validate tag format (tag = (ALPHA / DIGIT) *( *("-") (ALPHA / DIGIT)))
                    tagged_match_regex = r"^[a-zA-Z0-9]+(-*[a-zA-Z0-9]+)*$"
                    if not re.match(tagged_match_regex, tag):
                        raise ValueError(f"CAA tag contains disallowed character: {tag!r}")

                    # validate value format (value = *(%x21-3A / %x3C-7E))
                    for character in value:
                        if not (0x21 <= ord(character) <= 0x7E and character != ";"):
                            raise ValueError(f"CAA value contains disallowed character: {value!r}")

                    parameters[tag] = value
        else:
            issuer_domain_name = caa_value.strip()

        if not issuer_domain_name == "":  # empty domain name is valid for CAA
            domain_labels = issuer_domain_name.split(".")

            # validate label format (label = (ALPHA / DIGIT) *( *("-") (ALPHA / DIGIT)))
            domain_label_match_regex = r"^[a-zA-Z0-9]+(-*[a-zA-Z0-9]+)*$"
            is_valid = all(re.match(domain_label_match_regex, label) for label in domain_labels)

            if not is_valid:
                raise ValueError(f"CAA issuer domain name is not a valid domain name: {issuer_domain_name!r}")

        return issuer_domain_name, parameters
