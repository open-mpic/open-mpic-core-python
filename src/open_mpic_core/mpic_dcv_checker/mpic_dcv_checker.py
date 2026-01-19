import asyncio
import time
from contextlib import asynccontextmanager

import dns.asyncresolver
import requests
import re
import aiohttp
import base64

import ipaddress

from yarl import URL
from aiohttp import ClientError
from aiohttp.web import HTTPException

from open_mpic_core import DcvCheckRequest, DcvCheckResponse
from open_mpic_core import RedirectResponse, DcvUtils
from open_mpic_core import DcvValidationMethod, DnsRecordType
from open_mpic_core import MpicValidationError, ErrorMessages
from open_mpic_core import DomainEncoder
from open_mpic_core import DcvTlsAlpnValidator
from open_mpic_core import get_logger

logger = get_logger(__name__)


class ExpectedDnsRecordContent:
    def __init__(self, expected_value=None, possible_values=None, expected_parameters=None):
        self.expected_value = expected_value
        self.possible_values = None
        if self.expected_value is None:
            self.possible_values = possible_values
        self.expected_parameters = expected_parameters


# noinspection PyUnusedLocal
class MpicDcvChecker:
    WELL_KNOWN_PKI_PATH = ".well-known/pki-validation"
    WELL_KNOWN_ACME_PATH = ".well-known/acme-challenge"
    CONTACT_EMAIL_TAG = "contactemail"
    CONTACT_PHONE_TAG = "contactphone"
    # acme_tls_alpn related constants are in ./dcv_tls_alpn_validator.py

    def __init__(
        self,
        http_client_timeout: float = 30,
        verify_ssl: bool = False,
        log_level: int = None,
        dns_timeout: float = None,
        dns_resolution_lifetime: float = None,
    ):
        self.verify_ssl = verify_ssl
        self._async_http_client = None
        self._http_client_loop = None  # track which loop the http client was created on

        self.logger = logger.getChild(self.__class__.__name__)
        if log_level is not None:
            self.logger.setLevel(log_level)

        self.resolver = dns.asyncresolver.get_default_resolver()
        self.resolver.timeout = dns_timeout if dns_timeout is not None else self.resolver.timeout
        self.resolver.lifetime = (
            dns_resolution_lifetime if dns_resolution_lifetime is not None else self.resolver.lifetime
        )
        self.acme_tls_alpn_validator = DcvTlsAlpnValidator(log_level=log_level)
        self._http_client_timeout = http_client_timeout

    @asynccontextmanager
    async def get_async_http_client(self):
        connector = aiohttp.TCPConnector(ssl=self.verify_ssl, limit=0, force_close=True)
        dummy_cookie_jar = aiohttp.DummyCookieJar()  # disable cookie processing
        client = aiohttp.ClientSession(
            connector=connector,
            timeout=aiohttp.ClientTimeout(total=self._http_client_timeout),
            trust_env=True,
            cookie_jar=dummy_cookie_jar,
        )
        try:
            yield client
        finally:
            if not client.closed:
                await client.close()

    async def check_dcv(self, dcv_request: DcvCheckRequest) -> DcvCheckResponse:
        validation_method = dcv_request.dcv_check_parameters.validation_method
        # noinspection PyUnresolvedReferences
        self.logger.trace(
            "Checking DCV for %s with method %s. Trace ID: %s",
            dcv_request.domain_or_ip_target,
            validation_method,
            dcv_request.trace_identifier,
        )

        # encode domain if needed
        dcv_request.domain_or_ip_target = DomainEncoder.prepare_target_for_lookup(dcv_request.domain_or_ip_target)

        result = None
        match validation_method:
            case DcvValidationMethod.WEBSITE_CHANGE | DcvValidationMethod.ACME_HTTP_01:
                result = await self.perform_http_based_validation(dcv_request)
            case DcvValidationMethod.ACME_TLS_ALPN_01:
                result = await self.acme_tls_alpn_validator.perform_tls_alpn_validation(dcv_request)
            case _:  # all DNS based methods
                result = await self.perform_general_dns_validation(dcv_request)

        # noinspection PyUnresolvedReferences
        self.logger.trace(
            "Completed DCV for %s with method %s. Trace ID: %s",
            dcv_request.domain_or_ip_target,
            validation_method,
            dcv_request.trace_identifier,
        )
        return result

    async def perform_general_dns_validation(self, request: DcvCheckRequest) -> DcvCheckResponse:
        check_parameters = request.dcv_check_parameters
        validation_method = check_parameters.validation_method
        dns_name_prefix = check_parameters.dns_name_prefix
        dns_record_type = check_parameters.dns_record_type
        exact_match = True

        if dns_name_prefix is not None and len(dns_name_prefix) > 0:
            name_to_resolve = f"{dns_name_prefix}.{request.domain_or_ip_target}"
        else:
            name_to_resolve = request.domain_or_ip_target

        expected_dns_record_content = MpicDcvChecker.build_expected_dns_record_content(
            validation_method, check_parameters
        )

        if validation_method == DcvValidationMethod.DNS_CHANGE:  # DNS_CHANGE may allow for non-exact match
            exact_match = check_parameters.require_exact_match

        dcv_check_response = DcvUtils.create_empty_check_response(validation_method)

        try:
            # noinspection PyUnresolvedReferences
            async with self.logger.trace_timing(
                f"DNS lookup for target {name_to_resolve}. Trace ID: {request.trace_identifier}"
            ):
                lookup = await self.perform_dns_resolution(name_to_resolve, validation_method, dns_record_type)
            MpicDcvChecker.evaluate_dns_lookup_response(
                dcv_check_response, lookup, validation_method, dns_record_type, expected_dns_record_content, exact_match
            )
        except dns.exception.DNSException as e:
            log_msg = f"DNS lookup error for {name_to_resolve}: {str(e)}. Trace ID: {request.trace_identifier}"
            if isinstance(e, dns.resolver.NoAnswer) or isinstance(e, dns.resolver.NXDOMAIN):
                dcv_check_response.check_completed = True  # errors on the target domain, not the lookup
                # noinspection PyUnresolvedReferences
                self.logger.trace(log_msg)
            else:
                self.logger.warning(log_msg)
            dcv_check_response.errors = [
                MpicValidationError.create(ErrorMessages.DCV_LOOKUP_ERROR, e.__class__.__name__, e.msg)
            ]

        dcv_check_response.timestamp_ns = time.time_ns()
        return dcv_check_response

    async def perform_dns_resolution(self, name_to_resolve, validation_method, dns_record_type) -> dns.resolver.Answer:
        walk_domain_tree = validation_method in [
            DcvValidationMethod.CONTACT_EMAIL_CAA,
            DcvValidationMethod.CONTACT_PHONE_CAA,
        ]

        dns_rdata_type = dns.rdatatype.from_text(dns_record_type)
        lookup = None

        if walk_domain_tree:
            domain = dns.name.from_text(name_to_resolve)

            while domain != dns.name.root:
                try:
                    lookup = await self.resolver.resolve(qname=domain, rdtype=dns_rdata_type)
                    break
                except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
                    domain = domain.parent()
        else:
            domain = dns.name.from_text(name_to_resolve)  # to ensure trailing dot is added
            lookup = await self.resolver.resolve(qname=domain, rdtype=dns_rdata_type)
        return lookup

    @staticmethod
    def format_host_for_url(domain_or_ip_target: str) -> str:
        """Format host for URL, wrapping IPv6 addresses in square brackets if needed."""
        try:
            ip = ipaddress.ip_address(domain_or_ip_target)
            if isinstance(ip, ipaddress.IPv6Address):
                return f"[{domain_or_ip_target}]"
        except ValueError:
            pass
        return domain_or_ip_target

    async def perform_http_based_validation(self, request: DcvCheckRequest) -> DcvCheckResponse:
        validation_method = request.dcv_check_parameters.validation_method
        domain_or_ip_target = request.domain_or_ip_target
        formatted_host = MpicDcvChecker.format_host_for_url(domain_or_ip_target)
        http_headers = request.dcv_check_parameters.http_headers
        if validation_method == DcvValidationMethod.WEBSITE_CHANGE:
            expected_response_content = request.dcv_check_parameters.challenge_value
            url_scheme = request.dcv_check_parameters.url_scheme
            token_path = request.dcv_check_parameters.http_token_path
            token_url = (
                f"{url_scheme}://{formatted_host}/{MpicDcvChecker.WELL_KNOWN_PKI_PATH}/{token_path}"  # noqa E501 (http)
            )
            dcv_check_response = DcvUtils.create_empty_check_response(DcvValidationMethod.WEBSITE_CHANGE)
        else:
            expected_response_content = request.dcv_check_parameters.key_authorization
            token = request.dcv_check_parameters.token
            token_url = f"http://{formatted_host}/{MpicDcvChecker.WELL_KNOWN_ACME_PATH}/{token}"  # noqa E501 (http)
            dcv_check_response = DcvUtils.create_empty_check_response(DcvValidationMethod.ACME_HTTP_01)
        try:
            async with self.get_async_http_client() as async_http_client:
                # noinspection PyUnresolvedReferences
                async with self.logger.trace_timing(
                    f"HTTP lookup for target {token_url}, trace ID: {request.trace_identifier}"
                ):
                    async with async_http_client.get(url=token_url, headers=http_headers, max_redirects=20) as response:
                        dcv_check_response = await MpicDcvChecker.evaluate_http_lookup_response(
                            request, dcv_check_response, response, token_url, expected_response_content
                        )
        except asyncio.TimeoutError as e:
            dcv_check_response.timestamp_ns = time.time_ns()
            log_message = f"Timeout connecting to {token_url}: {str(e)}. Trace ID: {request.trace_identifier}"
            self.logger.warning(log_message)
            message = f"Connection timed out while attempting to connect to {token_url}"
            dcv_check_response.errors = [
                MpicValidationError.create(ErrorMessages.DCV_LOOKUP_ERROR, e.__class__.__name__, message)
            ]
        except (ClientError, HTTPException, OSError) as e:
            log_message = f"Error connecting to {token_url}: {str(e)}. Trace ID: {request.trace_identifier}"
            self.logger.error(log_message)
            dcv_check_response.timestamp_ns = time.time_ns()
            dcv_check_response.errors = [
                MpicValidationError.create(ErrorMessages.DCV_LOOKUP_ERROR, e.__class__.__name__, str(e))
            ]

        return dcv_check_response

    @staticmethod
    async def evaluate_http_lookup_response(
        dcv_check_request: DcvCheckRequest,
        dcv_check_response: DcvCheckResponse,
        http_response: aiohttp.ClientResponse,
        target_url: str,
        challenge_value: str,
    ):
        dcv_check_response.timestamp_ns = time.time_ns()
        dcv_check_response.check_completed = True
        response_history = None

        if http_response.status != requests.codes.OK:
            dcv_check_response.errors = [
                MpicValidationError.create(
                    ErrorMessages.GENERAL_HTTP_ERROR, str(http_response.status), http_response.reason
                )
            ]
        else:
            if (
                hasattr(http_response, "history")
                and http_response.history is not None
                and len(http_response.history) > 0
            ):
                response_history = [
                    RedirectResponse(status_code=resp.status, url=resp.headers["Location"])
                    for resp in http_response.history
                ]
                MpicDcvChecker.set_errors_on_invalid_response_history(dcv_check_response, response_history)

        if dcv_check_response.errors is None:
            match_regex = None
            bytes_to_read = max(100, len(challenge_value))  # read up to 100 bytes, unless challenge value is larger

            validation_method = dcv_check_request.dcv_check_parameters.validation_method
            if validation_method == DcvValidationMethod.WEBSITE_CHANGE:
                match_regex = dcv_check_request.dcv_check_parameters.match_regex
                if match_regex is not None and len(match_regex) > 0:
                    # read up to 100 bytes, unless challenge_value or match_regex is larger
                    bytes_to_read = max(100, len(challenge_value), len(match_regex))

            content = await http_response.content.read(bytes_to_read)
            # set internal _content to leverage decoding capabilities of ClientResponse.text without reading the entire response
            http_response._body = content
            response_text = await http_response.text()
            result = response_text.strip()

            if validation_method == DcvValidationMethod.ACME_HTTP_01:
                # ACME requires an exact match
                dcv_check_response.check_passed = challenge_value == result
            else:
                # Case-insensitive substring check for WEBSITE_CHANGE; also checks regex if provided
                dcv_check_response.check_passed = challenge_value.lower() in result.lower()
                if match_regex is not None and len(match_regex) > 0:
                    match = re.search(match_regex, result)
                    dcv_check_response.check_passed = challenge_value.lower() in result.lower() and match is not None
            dcv_check_response.details.response_status_code = http_response.status
            dcv_check_response.details.response_url = target_url
            dcv_check_response.details.response_history = response_history
            dcv_check_response.details.response_page = base64.b64encode(content).decode()

            http_response.close()  # ensure connection is closed

        return dcv_check_response

    @staticmethod
    def set_errors_on_invalid_response_history(dcv_check_response, response_history):
        """check if redirects included non-authorized response codes or ports and set errors if so"""
        for response in response_history:
            response_port = URL(response.url).port
            if (response.status_code not in (301, 302, 307, 308)) or (
                response_port is not None and response_port not in (80, 443)
            ):
                error = MpicValidationError.create(
                    ErrorMessages.INVALID_REDIRECT_ERROR, response.status_code, response.url
                )
                dcv_check_response.errors = [error]

    @staticmethod
    def evaluate_dns_lookup_response(
        dcv_check_response: DcvCheckResponse,
        dns_response: dns.resolver.Answer,
        validation_method: DcvValidationMethod,
        dns_record_type: DnsRecordType,
        expected_dns_record_content: ExpectedDnsRecordContent | None,
        exact_match: bool = True,
    ) -> None:
        if dns_response is None:
            dcv_check_response.check_passed = False
            dcv_check_response.check_completed = True
            return  # no response to evaluate
        response_code = dns_response.response.rcode()
        records_as_strings = []
        dns_rdata_type = dns.rdatatype.from_text(dns_record_type)
        for response_answer in dns_response.response.answer:
            if response_answer.rdtype == dns_rdata_type:
                for record_data in response_answer:
                    if validation_method == DcvValidationMethod.CONTACT_EMAIL_CAA:
                        if record_data.tag.decode("utf-8").lower() == MpicDcvChecker.CONTACT_EMAIL_TAG:
                            record_data_as_string = record_data.value.decode("utf-8")
                        else:
                            continue
                    elif validation_method == DcvValidationMethod.CONTACT_PHONE_CAA:
                        if record_data.tag.decode("utf-8").lower() == MpicDcvChecker.CONTACT_PHONE_TAG:
                            record_data_as_string = record_data.value.decode("utf-8")
                        else:
                            continue
                    else:
                        record_data_as_string = MpicDcvChecker.extract_value_from_record(record_data)
                    records_as_strings.append(record_data_as_string)

        dcv_check_response.details.response_code = response_code
        dcv_check_response.details.records_seen = records_as_strings
        dcv_check_response.details.ad_flag = (
            dns_response.response.flags & dns.flags.AD == dns.flags.AD
        )  # single ampersand
        cname_record_sets = dns_response.chaining_result.cnames
        cname_chain_str = []
        for cname_record_set in cname_record_sets:
            # This code will flatten a list of record sets should a CNAME come with multiple records in the record set.
            # Per the RFCs, there can only ever be one CNAME in a CNAME record set.
            for cname_record in cname_record_set:
                cname_chain_str.append(b".".join(cname_record.target.labels).decode("utf-8"))
        dcv_check_response.details.cname_chain = cname_chain_str
        dcv_check_response.details.found_at = dns_response.qname.to_text(omit_final_dot=True)

        # handle "special logic" validation methods first
        if validation_method == DcvValidationMethod.IP_ADDRESS:
            dcv_check_response.check_passed = MpicDcvChecker.is_expected_ip_address_in_response(
                expected_dns_record_content.expected_value, records_as_strings
            )
        elif validation_method == DcvValidationMethod.DNS_PERSISTENT:
            dcv_check_response.check_passed = MpicDcvChecker.evaluate_persistent_dns_response(
                expected_dns_record_content, records_as_strings
            )
        else:
            if validation_method == DcvValidationMethod.ACME_DNS_01:
                expected_dns_value = expected_dns_record_content.expected_value  # case-sensitive per ACME spec
            else:
                expected_dns_value = expected_dns_record_content.expected_value.lower()  # all others case-insensitive
                records_as_strings = [record.lower() for record in records_as_strings]

            # exact_match=True requires at least one record matches and will fail even if whitespace is different.
            # exact_match=False simply runs a contains check.
            if exact_match:
                dcv_check_response.check_passed = expected_dns_value in records_as_strings
            else:
                dcv_check_response.check_passed = any(
                    expected_dns_value in record for record in records_as_strings
                )

        dcv_check_response.check_completed = True

    @staticmethod
    def is_expected_ip_address_in_response(ip_address_as_string: str, records_as_strings: list[str]) -> bool:
        ip_address_found = False

        # compare IP addresses as objects, not strings, particularly to accommodate IPv6.
        try:
            expected_ip_address = ipaddress.ip_address(ip_address_as_string)
        except ValueError:
            expected_ip_address = None

        if expected_ip_address is not None:
            for seen_record_string in records_as_strings:
                try:
                    seen_ip_address = ipaddress.ip_address(seen_record_string)
                    if seen_ip_address == expected_ip_address:
                        ip_address_found = True
                        break
                except ValueError:
                    continue
        return ip_address_found

    @staticmethod
    def evaluate_persistent_dns_response(
        expected_dns_record_content: ExpectedDnsRecordContent,
        records_as_strings: list[str],
    ) -> bool:
        """
        Evaluate DNS TXT records for persistent validation per CA/Browser Forum requirements.
        Expected format follows RFC 8659 CAA issue-value syntax:
        "issuer-domain-name; accounturi=<uri>; persistUntil=<timestamp>"
        The persistUntil parameter is optional.
        """
        found_valid_record = False
        accepted_domain_names = [domain.lower() for domain in expected_dns_record_content.possible_values]
        expected_account_uri = expected_dns_record_content.expected_parameters['accounturi'].lower()

        for txt_record in records_as_strings:
            # Split on semicolon (parameter delimiter) and strip whitespace from each part
            parts = [part.strip() for part in txt_record.rstrip().split(";")]
            if len(parts) < 2:
                continue  # Need at least issuer-domain-name and one parameter

            issuer_domain_name = parts[0].lower()
            param_list = parts[1:]

            # First check issuer-domain-name matches one of the expected values
            if issuer_domain_name not in accepted_domain_names:
                continue

            # Look for required accounturi parameter
            valid_account_uri = False
            within_allowed_time = True  # Assume valid unless proven otherwise

            if not (len(param_list) == 1 and param_list[0].strip() == ""):  # if actual parameters follow the semicolon
                for parameter in param_list:
                    name_and_value = parameter.split("=", 1)
                    if len(name_and_value) != 2:
                        break  # malformed parameter; skip to next record
                    param_name = name_and_value[0].strip().lower()
                    param_value = name_and_value[1].strip()

                    if param_name == "accounturi":
                        if param_value.lower() == expected_account_uri:
                            valid_account_uri = True
                        else:
                            break  # accounturi does not match; skip to next record
                    elif param_name == "persistuntil":
                        try:
                            persist_until_in_seconds = int(param_value)  # seconds since epoch
                            current_seconds = int(time.time())
                            if persist_until_in_seconds < current_seconds:
                                within_allowed_time = False
                                break
                        except (ValueError, OSError):
                            within_allowed_time = False
                            break  # Invalid timestamp format
                        # Additional parameters are ignored per CA/Browser Forum spec

            # Record is valid if issuer matches, account URI matches, and not expired
            if valid_account_uri and within_allowed_time:
                found_valid_record = True

        return found_valid_record

    @staticmethod
    def build_expected_dns_record_content(
        validation_method: DcvValidationMethod,
        check_parameters,
    ) -> ExpectedDnsRecordContent:
        if validation_method == DcvValidationMethod.ACME_DNS_01:
            expected_content = ExpectedDnsRecordContent(expected_value=check_parameters.key_authorization_hash)
        elif validation_method == DcvValidationMethod.DNS_PERSISTENT:
            expected_content = ExpectedDnsRecordContent(
                expected_value=None,  # validated via issuer_domains and account_uri
                possible_values=check_parameters.issuer_domain_names,
                expected_parameters={"accounturi": check_parameters.expected_account_uri},
            )
        else:
            expected_content = ExpectedDnsRecordContent(expected_value=check_parameters.challenge_value)
        return expected_content

    # noinspection PyUnresolvedReferences
    @staticmethod
    def extract_value_from_record(record: dns.rdata.Rdata) -> str:
        record_value = None
        match record.rdtype:
            case dns.rdatatype.TXT:
                record_value = b"".join(record.strings).decode("utf-8")  # TODO errors='strict' or replace (lenient)?
            case dns.rdatatype.CAA:
                record_value = record.value.decode("utf-8")
            case dns.rdatatype.CNAME | dns.rdatatype.PTR:
                record_value = b".".join(record.target.labels).decode("utf-8")
            case dns.rdatatype.A | dns.rdatatype.AAAA:
                record_value = record.address
        return record_value
