import asyncio
import time
from contextlib import asynccontextmanager

import dns.asyncresolver
import requests
import re
import aiohttp
import base64

from aiohttp import ClientError
from aiohttp.web import HTTPException
from open_mpic_core import DcvCheckRequest, DcvCheckResponse
from open_mpic_core import RedirectResponse, DcvCheckResponseDetailsBuilder
from open_mpic_core import DcvValidationMethod, DnsRecordType
from open_mpic_core import MpicValidationError
from open_mpic_core import DomainEncoder
from open_mpic_core import get_logger

logger = get_logger(__name__)


# noinspection PyUnusedLocal
class MpicDcvChecker:
    WELL_KNOWN_PKI_PATH = ".well-known/pki-validation"
    WELL_KNOWN_ACME_PATH = ".well-known/acme-challenge"
    CONTACT_EMAIL_TAG = "contactemail"
    CONTACT_PHONE_TAG = "contactphone"

    def __init__(
        self, perspective_code: str, reuse_http_client: bool = False, verify_ssl: bool = False, log_level: int = None
    ):
        self.perspective_code = perspective_code
        self.verify_ssl = verify_ssl
        self._reuse_http_client = reuse_http_client
        self._async_http_client = None
        self._http_client_loop = None  # track which loop the http client was created on

        self.logger = logger.getChild(self.__class__.__name__)
        if log_level is not None:
            self.logger.setLevel(log_level)

    @asynccontextmanager
    async def get_async_http_client(self):
        current_loop = asyncio.get_running_loop()

        if self._reuse_http_client:  # implementations such as FastAPI may want this for efficiency
            reason_for_new_client = None
            # noinspection PyProtectedMember
            if self._async_http_client is None or self._async_http_client.closed:
                reason_for_new_client = "Creating new async HTTP client because there isn't an active one"
            elif self._http_client_loop is not current_loop:
                reason_for_new_client = "Creating new async HTTP client due to a mismatch in running event loops"

            if reason_for_new_client is not None:
                self.logger.debug(reason_for_new_client)
                if self._async_http_client and not self._async_http_client.closed:
                    await self._async_http_client.close()

                connector = aiohttp.TCPConnector(ssl=self.verify_ssl)
                self._async_http_client = aiohttp.ClientSession(
                    connector=connector, timeout=aiohttp.ClientTimeout(total=30)
                )
                self._http_client_loop = current_loop
            yield self._async_http_client
        else:  # implementations such as AWS Lambda will need a new client for each invocation
            connector = aiohttp.TCPConnector(ssl=self.verify_ssl)
            client = aiohttp.ClientSession(connector=connector, timeout=aiohttp.ClientTimeout(total=30))
            try:
                yield client
            finally:
                if not client.closed:
                    await client.close()

    async def initialize_async_http_client(self):
        """Initialize the async HTTP client.
        Needs to be called before the first HTTP based validation check.
        :return:
        """
        connector = aiohttp.TCPConnector(ssl=self.verify_ssl)  # flag to verify TLS certificates; defaults to False
        self._async_http_client = aiohttp.ClientSession(
            connector=connector,
            timeout=aiohttp.ClientTimeout(total=30),  # Add reasonable timeouts
        )

    async def shutdown(self):
        """Close the async HTTP client.

        Will need to call this as part of shutdown in wrapping code.
        For example, FastAPI's lifespan (https://fastapi.tiangolo.com/advanced/events/)
        :return:
        """
        if self._async_http_client and not self._async_http_client.closed:
            await self._async_http_client.close()
            self._async_http_client = None

    async def check_dcv(self, dcv_request: DcvCheckRequest) -> DcvCheckResponse:
        validation_method = dcv_request.dcv_check_parameters.validation_details.validation_method
        # noinspection PyUnresolvedReferences
        self.logger.trace(f"Checking DCV for {dcv_request.domain_or_ip_target} with method {validation_method}")

        # encode domain if needed
        dcv_request.domain_or_ip_target = DomainEncoder.prepare_target_for_lookup(dcv_request.domain_or_ip_target)

        result = None
        match validation_method:
            case DcvValidationMethod.WEBSITE_CHANGE_V2 | DcvValidationMethod.ACME_HTTP_01:
                result = await self.perform_http_based_validation(dcv_request)
            case _:  # ACME_DNS_01 | DNS_CHANGE | IP_LOOKUP | CONTACT_EMAIL | CONTACT_PHONE
                result = await self.perform_general_dns_validation(dcv_request)

        # noinspection PyUnresolvedReferences
        self.logger.trace(f"Completed DCV for {dcv_request.domain_or_ip_target} with method {validation_method}")
        return result

    async def perform_general_dns_validation(self, request) -> DcvCheckResponse:
        validation_details = request.dcv_check_parameters.validation_details
        validation_method = validation_details.validation_method
        dns_name_prefix = validation_details.dns_name_prefix
        dns_record_type = validation_details.dns_record_type
        exact_match = True

        if dns_name_prefix is not None and len(dns_name_prefix) > 0:
            name_to_resolve = f"{dns_name_prefix}.{request.domain_or_ip_target}"
        else:
            name_to_resolve = request.domain_or_ip_target

        if validation_method == DcvValidationMethod.ACME_DNS_01:
            expected_dns_record_content = validation_details.key_authorization
        else:
            expected_dns_record_content = validation_details.challenge_value
            exact_match = validation_details.require_exact_match

        dcv_check_response = self.create_empty_check_response(validation_method)

        try:
            # noinspection PyUnresolvedReferences
            async with self.logger.trace_timing(f"DNS lookup for target {name_to_resolve}"):
                lookup = await MpicDcvChecker.perform_dns_resolution(
                    name_to_resolve, validation_method, dns_record_type
                )
            MpicDcvChecker.evaluate_dns_lookup_response(
                dcv_check_response, lookup, validation_method, dns_record_type, expected_dns_record_content, exact_match
            )
        except dns.exception.DNSException as e:
            dcv_check_response.timestamp_ns = time.time_ns()
            dcv_check_response.errors = [MpicValidationError(error_type=e.__class__.__name__, error_message=e.msg)]
        return dcv_check_response

    @staticmethod
    async def perform_dns_resolution(name_to_resolve, validation_method, dns_record_type) -> dns.resolver.Answer:
        walk_domain_tree = (
            validation_method in [DcvValidationMethod.CONTACT_EMAIL, DcvValidationMethod.CONTACT_PHONE]
        ) and dns_record_type == DnsRecordType.CAA

        dns_rdata_type = dns.rdatatype.from_text(dns_record_type)
        lookup = None
        if walk_domain_tree:
            domain = dns.name.from_text(name_to_resolve)

            while domain != dns.name.root:
                try:
                    lookup = await dns.asyncresolver.resolve(domain, dns_rdata_type)
                    break
                except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
                    domain = domain.parent()
        else:
            lookup = await dns.asyncresolver.resolve(name_to_resolve, dns_rdata_type)
        return lookup

    async def perform_http_based_validation(self, request) -> DcvCheckResponse:
        validation_method = request.dcv_check_parameters.validation_details.validation_method
        domain_or_ip_target = request.domain_or_ip_target
        http_headers = request.dcv_check_parameters.validation_details.http_headers
        if validation_method == DcvValidationMethod.WEBSITE_CHANGE_V2:
            expected_response_content = request.dcv_check_parameters.validation_details.challenge_value
            url_scheme = request.dcv_check_parameters.validation_details.url_scheme
            token_path = request.dcv_check_parameters.validation_details.http_token_path
            token_url = f"{url_scheme}://{domain_or_ip_target}/{MpicDcvChecker.WELL_KNOWN_PKI_PATH}/{token_path}"  # noqa E501 (http)
            dcv_check_response = self.create_empty_check_response(DcvValidationMethod.WEBSITE_CHANGE_V2)
        else:
            expected_response_content = request.dcv_check_parameters.validation_details.key_authorization
            token = request.dcv_check_parameters.validation_details.token
            token_url = (
                f"http://{domain_or_ip_target}/{MpicDcvChecker.WELL_KNOWN_ACME_PATH}/{token}"  # noqa E501 (http)
            )
            dcv_check_response = self.create_empty_check_response(DcvValidationMethod.ACME_HTTP_01)
        try:
            async with self.get_async_http_client() as async_http_client:
                # noinspection PyUnresolvedReferences
                async with self.logger.trace_timing(f"HTTP lookup for target {token_url}"):
                    async with async_http_client.get(url=token_url, headers=http_headers) as response:
                        await MpicDcvChecker.evaluate_http_lookup_response(
                            request, dcv_check_response, response, token_url, expected_response_content
                        )
        except (ClientError, HTTPException) as e:
            dcv_check_response.timestamp_ns = time.time_ns()
            dcv_check_response.errors = [MpicValidationError(error_type=e.__class__.__name__, error_message=str(e))]
        return dcv_check_response

    def create_empty_check_response(self, validation_method: DcvValidationMethod) -> DcvCheckResponse:
        return DcvCheckResponse(
            perspective_code=self.perspective_code,
            check_passed=False,
            timestamp_ns=None,
            errors=None,
            details=DcvCheckResponseDetailsBuilder.build_response_details(validation_method),
        )

    @staticmethod
    async def evaluate_http_lookup_response(
        dcv_check_request: DcvCheckRequest,
        dcv_check_response: DcvCheckResponse,
        lookup_response: aiohttp.ClientResponse,
        target_url: str,
        challenge_value: str,
    ):
        response_history = None
        if (
            hasattr(lookup_response, "history")
            and lookup_response.history is not None
            and len(lookup_response.history) > 0
        ):
            response_history = [
                RedirectResponse(status_code=resp.status, url=resp.headers["Location"])
                for resp in lookup_response.history
            ]

        dcv_check_response.timestamp_ns = time.time_ns()

        if lookup_response.status == requests.codes.OK:
            bytes_to_read = max(100, len(challenge_value))  # read up to 100 bytes, unless challenge value is larger
            content = await lookup_response.content.read(bytes_to_read)
            # set internal _content to leverage decoding capabilities of ClientResponse.text without reading the entire response
            lookup_response._body = content
            response_text = await lookup_response.text()
            result = response_text.strip()
            expected_response_content = challenge_value
            validation_method = dcv_check_request.dcv_check_parameters.validation_details.validation_method
            if validation_method == DcvValidationMethod.ACME_HTTP_01:
                # need to match exactly for ACME HTTP-01
                dcv_check_response.check_passed = expected_response_content == result
            else:
                dcv_check_response.check_passed = expected_response_content in result
                match_regex = dcv_check_request.dcv_check_parameters.validation_details.match_regex
                if match_regex is not None and len(match_regex) > 0:
                    match = re.search(match_regex, result)
                    dcv_check_response.check_passed = dcv_check_response.check_passed and (match is not None)
            dcv_check_response.details.response_status_code = lookup_response.status
            dcv_check_response.details.response_url = target_url
            dcv_check_response.details.response_history = response_history
            dcv_check_response.details.response_page = base64.b64encode(content).decode()
        else:
            dcv_check_response.errors = [
                MpicValidationError(error_type=str(lookup_response.status), error_message=lookup_response.reason)
            ]

    @staticmethod
    def evaluate_dns_lookup_response(
        dcv_check_response: DcvCheckResponse,
        lookup_response: dns.resolver.Answer,
        validation_method: DcvValidationMethod,
        dns_record_type: DnsRecordType,
        expected_dns_record_content: str,
        exact_match: bool = True,
    ):
        response_code = lookup_response.response.rcode()
        records_as_strings = []
        dns_rdata_type = dns.rdatatype.from_text(dns_record_type)
        for response_answer in lookup_response.response.answer:
            if response_answer.rdtype == dns_rdata_type:
                for record_data in response_answer:
                    if validation_method == DcvValidationMethod.CONTACT_EMAIL and dns_record_type == DnsRecordType.CAA:
                        if record_data.tag.decode("utf-8").lower() == MpicDcvChecker.CONTACT_EMAIL_TAG:
                            record_data_as_string = record_data.value.decode("utf-8")
                        else:
                            continue
                    elif (
                        validation_method == DcvValidationMethod.CONTACT_PHONE and dns_record_type == DnsRecordType.CAA
                    ):
                        if record_data.tag.decode("utf-8").lower() == MpicDcvChecker.CONTACT_PHONE_TAG:
                            record_data_as_string = record_data.value.decode("utf-8")
                        else:
                            continue
                    else:
                        record_data_as_string = record_data.to_text()
                    # only need to remove enclosing quotes if they're there, e.g., for a TXT record
                    if record_data_as_string[0] == '"' and record_data_as_string[-1] == '"':
                        record_data_as_string = record_data_as_string[1:-1]
                    records_as_strings.append(record_data_as_string)

        dcv_check_response.details.response_code = response_code
        dcv_check_response.details.records_seen = records_as_strings
        dcv_check_response.details.ad_flag = (
            lookup_response.response.flags & dns.flags.AD == dns.flags.AD
        )  # single ampersand
        dcv_check_response.details.found_at = lookup_response.qname.to_text(omit_final_dot=True)

        if dns_record_type == DnsRecordType.CNAME:  # case-insensitive comparison -> convert strings to lowercase
            expected_dns_record_content = expected_dns_record_content.lower()
            records_as_strings = [record.lower() for record in records_as_strings]

        if exact_match:
            dcv_check_response.check_passed = expected_dns_record_content in records_as_strings
        else:
            dcv_check_response.check_passed = any(
                expected_dns_record_content in record for record in records_as_strings
            )
        dcv_check_response.timestamp_ns = time.time_ns()
