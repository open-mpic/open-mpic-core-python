import time
import dns.resolver
import requests
import urllib3
from dns.rdatatype import RdataType

from open_mpic_core.common_domain.check_request import DcvCheckRequest
from open_mpic_core.common_domain.check_response import DcvCheckResponse
from open_mpic_core.common_domain.check_response_details import RedirectResponse, DcvCheckResponseDetailsBuilder
from open_mpic_core.common_domain.enum.dcv_validation_method import DcvValidationMethod
from open_mpic_core.common_domain.remote_perspective import RemotePerspective
from open_mpic_core.common_domain.validation_error import MpicValidationError
import base64


# noinspection PyUnusedLocal
class MpicDcvChecker:
    WELL_KNOWN_PKI_PATH = '.well-known/pki-validation'
    WELL_KNOWN_ACME_PATH = '.well-known/acme-challenge'

    def __init__(self, perspective: RemotePerspective):
        self.perspective = perspective
        # TODO self.dns_resolver = dns.resolver.Resolver() -- set up a way to use Unbound here... maybe take a config?

    def check_dcv(self, dcv_request: DcvCheckRequest) -> DcvCheckResponse:
        match dcv_request.dcv_check_parameters.validation_details.validation_method:
            case DcvValidationMethod.WEBSITE_CHANGE_V2:
                return self.perform_website_change_validation(dcv_request)
            case DcvValidationMethod.DNS_CHANGE:
                return self.perform_dns_change_validation(dcv_request)
            case DcvValidationMethod.ACME_HTTP_01:
                return self.perform_acme_http_01_validation(dcv_request)
            case DcvValidationMethod.ACME_DNS_01:
                return self.perform_acme_dns_01_validation(dcv_request)

    def perform_website_change_validation(self, request) -> DcvCheckResponse:
        domain_or_ip_target = request.domain_or_ip_target  # TODO optionally iterate up through the domain hierarchy
        url_scheme = request.dcv_check_parameters.validation_details.url_scheme
        token_path = request.dcv_check_parameters.validation_details.http_token_path
        token_url = f"{url_scheme}://{domain_or_ip_target}/{MpicDcvChecker.WELL_KNOWN_PKI_PATH}/{token_path}"  # noqa E501 (http)
        expected_response_content = request.dcv_check_parameters.validation_details.challenge_value
        dcv_check_response = self.create_empty_check_response(DcvValidationMethod.WEBSITE_CHANGE_V2)

        try:
            response = requests.get(url=token_url, stream=True)  # FIXME should probably add a timeout here.. but how long?
            MpicDcvChecker.evaluate_http_lookup_response(dcv_check_response, response, token_url, expected_response_content)
        except requests.exceptions.RequestException as e:
            dcv_check_response.timestamp_ns = time.time_ns()
            dcv_check_response.errors = [MpicValidationError(error_type=e.__class__.__name__, error_message=str(e))]

        return dcv_check_response

    def perform_dns_change_validation(self, request) -> DcvCheckResponse:
        domain_or_ip_target = request.domain_or_ip_target
        dns_name_prefix = request.dcv_check_parameters.validation_details.dns_name_prefix
        dns_record_type = dns.rdatatype.from_text(request.dcv_check_parameters.validation_details.dns_record_type)
        if dns_name_prefix is not None and len(dns_name_prefix) > 0:
            name_to_resolve = f"{dns_name_prefix}.{domain_or_ip_target}"
        else:
            name_to_resolve = domain_or_ip_target
        expected_dns_record_content = request.dcv_check_parameters.validation_details.challenge_value
        dcv_check_response = self.create_empty_check_response(DcvValidationMethod.DNS_CHANGE)

        try:
            # TODO add leading underscore to name_to_resolve if it's not found?
            lookup = dns.resolver.resolve(name_to_resolve, dns_record_type)
            MpicDcvChecker.evaluate_dns_lookup_response(dcv_check_response, lookup, dns_record_type, expected_dns_record_content)
        except dns.exception.DNSException as e:
            dcv_check_response.timestamp_ns = time.time_ns()
            dcv_check_response.errors = [MpicValidationError(error_type=e.__class__.__name__, error_message=e.msg)]

        return dcv_check_response

    def perform_acme_http_01_validation(self, request) -> DcvCheckResponse:
        domain_or_ip_target = request.domain_or_ip_target
        token = request.dcv_check_parameters.validation_details.token
        expected_response_content = request.dcv_check_parameters.validation_details.key_authorization
        token_url = f"http://{domain_or_ip_target}/{MpicDcvChecker.WELL_KNOWN_ACME_PATH}/{token}"  # noqa E501 (http)
        dcv_check_response = self.create_empty_check_response(DcvValidationMethod.ACME_HTTP_01)

        try:
            urllib3.disable_warnings(category=urllib3.exceptions.InsecureRequestWarning)
            response = requests.get(url=token_url, stream=True, verify=False)  # don't verify SSL so can follow redirects to HTTPS (correct?)
            MpicDcvChecker.evaluate_http_lookup_response(dcv_check_response, response, token_url, expected_response_content)
        except requests.exceptions.RequestException as e:
            dcv_check_response.timestamp_ns = time.time_ns()
            dcv_check_response.errors = [MpicValidationError(error_type=e.__class__.__name__, error_message=str(e))]

        return dcv_check_response

    def perform_acme_dns_01_validation(self, request) -> DcvCheckResponse:
        domain_or_ip_target = request.domain_or_ip_target
        dns_record_type = dns.rdatatype.TXT
        name_to_resolve = f"_acme-challenge.{domain_or_ip_target}"
        expected_dns_record_content = request.dcv_check_parameters.validation_details.key_authorization
        dcv_check_response = self.create_empty_check_response(DcvValidationMethod.DNS_CHANGE)

        try:
            lookup = dns.resolver.resolve(name_to_resolve, dns_record_type)
            MpicDcvChecker.evaluate_dns_lookup_response(dcv_check_response, lookup, dns.rdatatype.TXT, expected_dns_record_content)
        except dns.exception.DNSException as e:
            dcv_check_response.timestamp_ns = time.time_ns()
            dcv_check_response.errors = [MpicValidationError(error_type=e.__class__.__name__, error_message=e.msg)]

        return dcv_check_response

    def create_empty_check_response(self, validation_method: DcvValidationMethod) -> DcvCheckResponse:
        return DcvCheckResponse(
            perspective_code=self.perspective.code,
            check_passed=False,
            timestamp_ns=None,
            errors=None,
            details=DcvCheckResponseDetailsBuilder.build_response_details(validation_method)
        )

    @staticmethod
    def evaluate_http_lookup_response(dcv_check_response: DcvCheckResponse, lookup_response: requests.Response, target_url: str, challenge_value: str):
        # TODO introduce a test to ensure that only the first 100 bytes of a potentially gigantic response are ever read. Important to prevent an attacker, for example, to force the CA to incur in excessive egress o large Lambda execution times cost.
        content = lookup_response.raw.read(100)

        response_history = None
        if hasattr(lookup_response, 'history') and lookup_response.history is not None and len(lookup_response.history) > 0:
            response_history = [
                RedirectResponse(status_code=resp.status_code, url=resp.headers['Location'])
                for resp in lookup_response.history
            ]

        dcv_check_response.timestamp_ns = time.time_ns()

        if lookup_response.status_code == requests.codes.OK:
            # Setting the internal Response._content to leverage decoding capabilities of Response.text without reading the entire response.
            lookup_response._content = content
            result = lookup_response.text.strip()
            expected_response_content = challenge_value
            dcv_check_response.check_passed = (result == expected_response_content)
            dcv_check_response.details.response_status_code = lookup_response.status_code
            dcv_check_response.details.response_url = target_url
            dcv_check_response.details.response_history = response_history
            dcv_check_response.details.response_page = base64.b64encode(content).decode()
        else:
            dcv_check_response.errors = [
                MpicValidationError(error_type=str(lookup_response.status_code), error_message=lookup_response.reason)]

    @staticmethod
    def evaluate_dns_lookup_response(dcv_check_response: DcvCheckResponse, lookup_response: dns.resolver.Answer, dns_record_type: RdataType, expected_dns_record_content: str):
        response_code = lookup_response.response.rcode()
        records_as_strings = []
        for response_answer in lookup_response.response.answer:
            if response_answer.rdtype == dns_record_type:
                for record_data in response_answer:
                    record_data_as_string = record_data.to_text()
                    # only need to remove enclosing quotes if they're there, e.g., for a TXT record
                    if record_data_as_string[0] == '"' and record_data_as_string[-1] == '"':
                        record_data_as_string = record_data_as_string[1:-1]
                    records_as_strings.append(record_data_as_string)

        dcv_check_response.check_passed = expected_dns_record_content in records_as_strings
        dcv_check_response.timestamp_ns = time.time_ns()
        dcv_check_response.details.records_seen = records_as_strings
        dcv_check_response.details.response_code = response_code
        dcv_check_response.details.ad_flag = lookup_response.response.flags & dns.flags.AD == dns.flags.AD  # single ampersand
