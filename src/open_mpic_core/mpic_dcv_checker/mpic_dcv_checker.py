import base64
import time
import dns.resolver
import requests

from open_mpic_core.common_domain.check_request import DcvCheckRequest
from open_mpic_core.common_domain.check_response import DcvCheckResponse
from open_mpic_core.common_domain.check_response_details import DcvDnsChangeResponseDetails, \
    DcvWebsiteChangeResponseDetails, RedirectResponse
from open_mpic_core.common_domain.enum.dcv_validation_method import DcvValidationMethod
from open_mpic_core.common_domain.remote_perspective import RemotePerspective
from open_mpic_core.common_domain.validation_error import MpicValidationError


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

    def perform_website_change_validation(self, request) -> DcvCheckResponse:
        domain_or_ip_target = request.domain_or_ip_target  # TODO optionally iterate up through the domain hierarchy
        url_scheme = request.dcv_check_parameters.validation_details.url_scheme
        token_path = request.dcv_check_parameters.validation_details.http_token_path
        token_url = f"{url_scheme}://{domain_or_ip_target}/{MpicDcvChecker.WELL_KNOWN_PKI_PATH}/{token_path}"  # noqa E501 (http)
        expected_response_content = request.dcv_check_parameters.validation_details.challenge_value

        dcv_check_response = DcvCheckResponse(
            perspective_code=self.perspective.code,
            check_passed=False,
            timestamp_ns=None,
            errors=None,
            details=DcvWebsiteChangeResponseDetails(
                response_status_code=None,
                response_history=None,
                response_page=None,
            )
        )

        try:
            response = requests.get(token_url, stream=True)  # FIXME should probably add a timeout here.. but how long?

            content = response.raw.read(100)
            decoded_content = content.decode('utf-8')
            base64_encoded_content = base64.b64encode(content) if content is not None else None

            response_history = None
            if hasattr(response, 'history') and response.history is not None and len(response.history) > 0:
                response_history = [
                    RedirectResponse(status_code=resp.status_code, url=resp.headers['Location'])
                    for resp in response.history
                ]

            dcv_check_response.timestamp_ns = time.time_ns()

            if response.status_code == requests.codes.OK:
                result = response.text.strip()
                dcv_check_response.check_passed = (result == expected_response_content)
                dcv_check_response.details.response_status_code = response.status_code
                dcv_check_response.details.response_url = token_url
                dcv_check_response.details.response_history = response_history
                dcv_check_response.details.response_page = base64_encoded_content
            else:
                dcv_check_response.errors = [MpicValidationError(error_type=str(response.status_code), error_message=response.reason)]
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

        # TODO add leading underscore to name_to_resolve if it's not found?

        dcv_check_response = DcvCheckResponse(
            perspective_code=self.perspective.code,
            check_passed=False,
            timestamp_ns=None,
            errors=None,
            details=DcvDnsChangeResponseDetails(
                records_seen=None,
            )
        )

        try:
            lookup = dns.resolver.resolve(name_to_resolve, dns_record_type)
            response_code = lookup.response.rcode
            records_as_strings = []
            for response_answer in lookup.response.answer:
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
            dcv_check_response.details.ad_flag = lookup.response.flags & dns.flags.AD == dns.flags.AD  # single ampersand
        except dns.exception.DNSException as e:
            dcv_check_response.timestamp_ns = time.time_ns()
            dcv_check_response.errors = [MpicValidationError(error_type=e.__class__.__name__, error_message=e.msg)]

        return dcv_check_response
