import re
import time
from typing import Final, Optional
import dns.resolver
import dns.asyncresolver
from dns.name import Name
from dns.rrset import RRset
from pydantic import BaseModel
from uritools import isuri

from opentelemetry.trace import Status, StatusCode

from open_mpic_core import CaaCheckRequest, CaaCheckResponse, CaaCheckResponseDetails
from open_mpic_core import MpicValidationError, ErrorMessages
from open_mpic_core import DomainEncoder
from open_mpic_core import get_logger
from open_mpic_core import get_meter, get_tracer
from open_mpic_core import CertificateType

ISSUE_TAG: Final[str] = "issue"
ISSUEWILD_TAG: Final[str] = "issuewild"
ISSUEMAIL_TAG: Final[str] = "issuemail"
IODEF_TAG: Final[str] = "iodef"
# to accommodate email and phone based DCV that gets contact info from CAA records
CONTACTEMAIL_TAG: Final[str] = "contactemail"
CONTACTPHONE_TAG: Final[str] = "contactphone"
# RFC 8657 parameters for issue and issuewild properties
ACCOUNTURI_PARAMETER_TAG: Final[str] = "accounturi"
VALIDATIONMETHODS_PARAMETER_TAG: Final[str] = "validationmethods"
# RFC 8657 section 4: label = 1*(ALPHA / DIGIT / "-")
VALIDATION_METHOD_LABEL_REGEX: Final[re.Pattern] = re.compile(r"^[a-zA-Z0-9-]+$")

logger = get_logger(__name__)


class MpicCaaLookupException(Exception):  # This is a python exception type used for raise statements.
    pass


class CaaIssuanceEvaluation(BaseModel):
    issuance_permitted: bool
    # The fields below are only meaningful when issuance_permitted is False.
    # True if at least one CAA record would permit issuance but for its RFC 8657 accounturi and/or
    # validationmethods parameters (i.e., those parameters were the sole reason no CAA record permitted issuance).
    rfc_8657_parameters_blocked_issuance: bool = False
    # accounturi values seen that would have permitted issuance had they been supplied in accounturi_values
    permissible_under_account_uri: list[str] = []
    # validation method labels seen that would have permitted issuance had they been supplied in validation_methods
    permissible_under_validation_method: list[str] = []


class MpicCaaChecker:
    def __init__(
        self,
        default_caa_domain_list: list[str],
        log_level: int | None = None,
        dns_timeout: float | None = None,
        dns_resolution_lifetime: float | None = None,
    ):
        self.default_caa_domain_list = default_caa_domain_list

        self.logger = logger.getChild(self.__class__.__name__)
        if log_level is not None:
            self.logger.setLevel(log_level)

        self.resolver = dns.asyncresolver.get_default_resolver()
        self.resolver.timeout = dns_timeout if dns_timeout is not None else self.resolver.timeout
        self.resolver.lifetime = (
            dns_resolution_lifetime if dns_resolution_lifetime is not None else self.resolver.lifetime
        )

        _meter = get_meter(__name__)
        self._tracer = get_tracer(__name__)
        self._request_counter = _meter.create_counter(
            "mpic.caa.requests",
            description="Total CAA check requests processed",
            unit="1",
        )
        self._duration_histogram = _meter.create_histogram(
            "mpic.caa.duration",
            description="CAA check request duration",
            unit="ms",
        )
        self._dns_duration_histogram = _meter.create_histogram(
            "mpic.caa.dns_lookup.duration",
            description="CAA DNS lookup duration",
            unit="ms",
        )

    async def find_caa_records_and_domain(self, caa_request) -> tuple[RRset, Name]:
        _dns_start_ns = time.perf_counter_ns()
        rrset = None
        domain = dns.name.from_text(caa_request.domain_or_ip_target)
        with self._tracer.start_as_current_span("mpic.caa.dns_lookup"):
            try:
                while domain != dns.name.root:
                    try:
                        lookup = await self.resolver.resolve(domain, dns.rdatatype.CAA)
                        rrset = lookup.rrset
                        break
                    except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
                        domain = domain.parent()
                    # will raise other exceptions that we want to catch in the calling function
            finally:
                self._dns_duration_histogram.record((time.perf_counter_ns() - _dns_start_ns) / 1_000_000)

        return rrset, domain

    async def check_caa(self, caa_request: CaaCheckRequest) -> CaaCheckResponse:
        # noinspection PyUnresolvedReferences
        self.logger.trace(f"Checking CAA for {caa_request.domain_or_ip_target}")

        # Assume the default system configured validation targets and override if sent in the API call.
        caa_domains = self.default_caa_domain_list
        is_wc_domain = False
        certificate_type = CertificateType.TLS_SERVER
        accounturi_values = None
        validation_methods = None
        if caa_request.caa_check_parameters:
            certificate_type = caa_request.caa_check_parameters.certificate_type  # defaults to TLS_SERVER
            accounturi_values = caa_request.caa_check_parameters.accounturi_values
            validation_methods = caa_request.caa_check_parameters.validation_methods
            if caa_request.caa_check_parameters.caa_domains:
                caa_domains = caa_request.caa_check_parameters.caa_domains

        # Use the domain name to determine if it is a wildcard domain
        # check if domain or ip target has an asterisk as its lowest (first) label (e.g. *.example.com)
        if caa_request.domain_or_ip_target.startswith("*."):
            is_wc_domain = True

        error_encountered = False
        caa_lookup_error = None
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

        _start_ns = time.perf_counter_ns()
        with self._tracer.start_as_current_span("mpic.caa.check") as _span:
            try:
                # encode domain if needed
                caa_request.domain_or_ip_target = DomainEncoder.prepare_target_for_lookup(
                    caa_request.domain_or_ip_target
                )

                # noinspection PyUnresolvedReferences
                async with self.logger.trace_timing(f"CAA lookup for target {caa_request.domain_or_ip_target}"):
                    rrset, domain = await self.find_caa_records_and_domain(caa_request)
                caa_found = rrset is not None
            except Exception as e:
                error_encountered = True
                caa_lookup_error = e
                error_message = f"Error during CAA lookup for {caa_request.domain_or_ip_target}: {e}. Trace ID: {caa_request.trace_identifier}"
                self.logger.error(error_message)
                caa_check_response.errors = [MpicValidationError.create(ErrorMessages.CAA_LOOKUP_ERROR, error_message)]
                caa_check_response.details.found_at = None
                caa_check_response.details.records_seen = None

            if error_encountered:  # if there was an error during lookup
                _span.record_exception(caa_lookup_error)
                _span.set_status(Status(StatusCode.ERROR, description=type(caa_lookup_error).__name__))
                # check if allow_lookup_failure is set to True, and allow issuance depending on error
                if isinstance(caa_lookup_error, (dns.resolver.LifetimeTimeout, dns.resolver.NoNameservers)):
                    if caa_request.caa_check_parameters and caa_request.caa_check_parameters.allow_lookup_failure:
                        # if the error was from the lookup process itself (e.g. timeout), allow issuance
                        caa_check_response.check_completed = True
                        caa_check_response.check_passed = True
            elif not caa_found:  # if domain has no CAA records: valid for issuance
                caa_check_response.check_completed = True
                caa_check_response.check_passed = True
                caa_check_response.details.caa_record_present = False
                caa_check_response.details.found_at = None
                caa_check_response.details.records_seen = None
            else:
                caa_check_response.check_completed = True
                evaluation = MpicCaaChecker.evaluate_rrset_for_issuance(
                    caa_domains, certificate_type, is_wc_domain, rrset, accounturi_values, validation_methods
                )
                caa_check_response.check_passed = evaluation.issuance_permitted
                if not evaluation.issuance_permitted and evaluation.rfc_8657_parameters_blocked_issuance:
                    # RFC 8657 parameters were the sole reason no CAA record permitted issuance
                    caa_check_response.details.permissible_under_account_uri = evaluation.permissible_under_account_uri
                    caa_check_response.details.permissible_under_validation_method = (
                        evaluation.permissible_under_validation_method
                    )
                caa_check_response.details.caa_record_present = True
                caa_check_response.details.found_at = domain.to_text(omit_final_dot=True)
                caa_check_response.details.records_seen = [record_data.to_text() for record_data in rrset]
            caa_check_response.timestamp_ns = time.time_ns()

            elapsed_ms = (time.perf_counter_ns() - _start_ns) / 1_000_000
            self._duration_histogram.record(
                elapsed_ms,
                {"check.passed": caa_check_response.check_passed},
            )
            self._request_counter.add(
                1,
                {
                    "check.passed": caa_check_response.check_passed,
                    "check.completed": caa_check_response.check_completed,
                    "caa.lookup_error": error_encountered,
                },
            )

        # noinspection PyUnresolvedReferences
        self.logger.trace(f"Completed CAA for {caa_request.domain_or_ip_target}")
        return caa_check_response

    @staticmethod
    def evaluate_rrset_for_issuance(
        caa_domains,
        certificate_type: CertificateType,
        is_wc_domain,
        rrset,
        accounturi_values: Optional[list[str]] = None,
        validation_methods: Optional[list[str]] = None,
    ) -> CaaIssuanceEvaluation:
        issue_tag_values = []
        issuewild_tag_values = []
        issuemail_tag_values = []
        has_unknown_critical_flags = False

        # Note: a record with critical flag and 'issue' tag will be considered valid for issuance
        for resource_record in rrset:
            tag = resource_record.tag.decode("utf-8")
            tag_lower = tag.lower()
            val = resource_record.value.decode("utf-8")
            if tag_lower == ISSUE_TAG:
                issue_tag_values.append(val)
            elif tag_lower == ISSUEWILD_TAG:
                issuewild_tag_values.append(val)
            elif tag_lower == ISSUEMAIL_TAG:
                issuemail_tag_values.append(val)
            elif (
                not (tag_lower in [CONTACTEMAIL_TAG, CONTACTPHONE_TAG, IODEF_TAG])
                and resource_record.flags & 0b10000000
            ):  # bitwise-and to check if flags are 128 (the critical flag)
                has_unknown_critical_flags = True

        if has_unknown_critical_flags:
            evaluation = CaaIssuanceEvaluation(issuance_permitted=False)
        elif certificate_type == CertificateType.S_MIME:
            if len(issuemail_tag_values) > 0:
                # RFC 8657 only defines its parameters for issue and issuewild properties; they are ignored for issuemail
                evaluation = MpicCaaChecker.evaluate_caa_values_for_issuance(issuemail_tag_values, caa_domains)
            else:
                # No issue mail tags
                evaluation = CaaIssuanceEvaluation(issuance_permitted=True)
        elif certificate_type == CertificateType.TLS_SERVER:
            if is_wc_domain and len(issuewild_tag_values) > 0:
                evaluation = MpicCaaChecker.evaluate_caa_values_for_issuance(
                    issuewild_tag_values, caa_domains, accounturi_values, validation_methods
                )
            elif len(issue_tag_values) > 0:
                evaluation = MpicCaaChecker.evaluate_caa_values_for_issuance(
                    issue_tag_values, caa_domains, accounturi_values, validation_methods
                )
            else:
                # We had no unknown critical tags, and we found no issue tags. Issuance can proceed.
                evaluation = CaaIssuanceEvaluation(issuance_permitted=True)
        else:
            # This is the case of an unimplemented certificate type. We cannot determine if issuance is valid or not. This case should never be hit as all values of the certificate type enum should be tested for in the above logic.
            evaluation = CaaIssuanceEvaluation(issuance_permitted=False)
        return evaluation

    @staticmethod
    def evaluate_caa_values_for_issuance(
        value_list: list,
        caa_domains,
        accounturi_values: Optional[list[str]] = None,
        validation_methods: Optional[list[str]] = None,
    ) -> CaaIssuanceEvaluation:
        evaluation = CaaIssuanceEvaluation(issuance_permitted=False)
        permissible_account_uris = []
        permissible_validation_method_labels = []
        for value in value_list:
            try:
                domain, parameter_pairs = MpicCaaChecker.extract_domain_and_parameters_from_caa_value(value)
            except ValueError as ve:
                logger.warning(f"Error parsing CAA value: {ve}")
                continue
            if domain.lower() not in caa_domains:  # if the value is not in the list of valid CAA domains
                continue
            # The domain matches; evaluate the property's RFC 8657 parameters (if enforcement was requested).
            accounturi_satisfied, accounturis_seen = MpicCaaChecker.evaluate_accounturi_parameter(
                parameter_pairs, accounturi_values
            )
            validationmethods_satisfied, method_labels_seen = MpicCaaChecker.evaluate_validationmethods_parameter(
                parameter_pairs, validation_methods
            )
            if accounturi_satisfied and validationmethods_satisfied:
                evaluation.issuance_permitted = True
                break
            # This property would have permitted issuance but for its RFC 8657 parameters.
            evaluation.rfc_8657_parameters_blocked_issuance = True
            permissible_account_uris.extend(accounturis_seen)
            permissible_validation_method_labels.extend(method_labels_seen)

        if not evaluation.issuance_permitted:
            # dedupe values seen across properties while preserving order
            evaluation.permissible_under_account_uri = list(dict.fromkeys(permissible_account_uris))
            evaluation.permissible_under_validation_method = list(dict.fromkeys(permissible_validation_method_labels))
        return evaluation

    @staticmethod
    def evaluate_accounturi_parameter(
        parameter_pairs: list[tuple[str, str]], accounturi_values: Optional[list[str]]
    ) -> tuple[bool, list[str]]:
        """
        Evaluates a property's RFC 8657 accounturi parameter against the permissible account URIs for the request.
        Returns (satisfied, accounturis_seen) where accounturis_seen contains the accounturi value that would have
        permitted issuance had it been supplied in accounturi_values (empty if the parameter was satisfied).
        """
        if accounturi_values is None:
            return True, []
        # per the RFC 8659 grammar, parameter tags are matched case-sensitively (unlike property tags)
        accounturis = [value for tag, value in parameter_pairs if tag == ACCOUNTURI_PARAMETER_TAG]
        if len(accounturis) == 0:
            # a property without an accounturi parameter matches any account (RFC 8657 section 3)
            return True, []
        if len(accounturis) > 1:
            # a property with multiple accounturi parameters is unsatisfiable (RFC 8657 section 3)
            return False, []
        accounturi = accounturis[0]
        if not isuri(accounturi):
            # a property with an invalid accounturi parameter is unsatisfiable (RFC 8657 section 3)
            return False, []
        if accounturi in accounturi_values:
            return True, []
        return False, [accounturi]

    @staticmethod
    def evaluate_validationmethods_parameter(
        parameter_pairs: list[tuple[str, str]], validation_methods: Optional[list[str]]
    ) -> tuple[bool, list[str]]:
        """
        Evaluates a property's RFC 8657 validationmethods parameters against the permissible validation method labels
        for the request. Returns (satisfied, method_labels_seen) where method_labels_seen contains the labels that
        would have permitted issuance had they been supplied in validation_methods (empty if the parameter was
        satisfied).
        """
        if validation_methods is None:
            return True, []
        parameter_values = [value for tag, value in parameter_pairs if tag == VALIDATIONMETHODS_PARAMETER_TAG]
        if len(parameter_values) == 0:
            # a property without a validationmethods parameter is satisfied by any validation method
            return True, []
        label_lists = []
        for parameter_value in parameter_values:
            # an empty value is well-formed per the RFC 8657 ABNF (zero labels) but is satisfied by no method
            labels = parameter_value.split(",") if parameter_value != "" else []
            if not all(VALIDATION_METHOD_LABEL_REGEX.match(label) for label in labels):
                # treat a property with a malformed validationmethods parameter as unsatisfiable
                return False, []
            label_lists.append(labels)
        # RFC 8657 section 4 constrains the property per parameter; if the parameter appears multiple times, the
        # validation method in use must therefore be listed in each occurrence's comma-separated label list
        permissible_labels = [label for label in label_lists[0] if all(label in labels for labels in label_lists[1:])]
        permissible_labels = list(dict.fromkeys(permissible_labels))  # dedupe while preserving order
        if any(method in permissible_labels for method in validation_methods):
            return True, []
        return False, permissible_labels

    @staticmethod
    def extract_domain_and_parameters_from_caa_value(caa_value: str) -> tuple[str, list[tuple[str, str]]]:
        # Split on semicolons since they're prohibited in parameter tag/value
        parameters = []
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

                    parameters.append((tag, value))
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
