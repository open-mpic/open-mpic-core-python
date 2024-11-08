from open_mpic_core.common_domain.check_parameters import DcvCheckParameters, DcvWebsiteChangeValidationDetails, \
    DcvDnsChangeValidationDetails, CaaCheckParameters
from open_mpic_core.common_domain.check_request import DcvCheckRequest, CaaCheckRequest
from open_mpic_core.common_domain.check_response import DcvCheckResponse
from open_mpic_core.common_domain.check_response_details import DcvWebsiteChangeResponseDetails, \
    DcvDnsChangeResponseDetails
from open_mpic_core.common_domain.enum.certificate_type import CertificateType
from open_mpic_core.common_domain.enum.dns_record_type import DnsRecordType
from open_mpic_core.common_domain.enum.url_scheme import UrlScheme


class ValidCheckCreator:
    @staticmethod
    def create_valid_caa_check_request():
        return CaaCheckRequest(domain_or_ip_target='example.com',
                               caa_check_parameters=CaaCheckParameters(
                                   certificate_type=CertificateType.TLS_SERVER, caa_domains=['ca1.com']
                               ))

    @staticmethod
    def create_valid_http_check_request():
        return DcvCheckRequest(domain_or_ip_target='example.com',
                               dcv_check_parameters=DcvCheckParameters(
                                   validation_details=DcvWebsiteChangeValidationDetails(
                                       http_token_path='/.well-known/pki_validation/token111_ca1.txt',
                                       challenge_value='challenge_111',
                                       url_scheme=UrlScheme.HTTP
                                   )
                               ))

    @staticmethod
    def create_valid_dns_check_request(record_type=DnsRecordType.TXT):
        return DcvCheckRequest(domain_or_ip_target='example.com',
                               dcv_check_parameters=DcvCheckParameters(
                                   validation_details=DcvDnsChangeValidationDetails(
                                       dns_name_prefix='_dnsauth',
                                       dns_record_type=record_type,
                                       challenge_value=f"{record_type}_challenge_111.ca1.com.")
                               ))

    @staticmethod
    def create_valid_http_check_request_and_response(perspective_code: str) -> tuple[DcvCheckRequest, DcvCheckResponse]:
        request = ValidCheckCreator.create_valid_http_check_request()
        url_scheme = request.dcv_check_parameters.validation_details.url_scheme
        http_token_path = request.dcv_check_parameters.validation_details.http_token_path
        domain_or_ip = request.domain_or_ip_target
        response = DcvCheckResponse(
            perspective_code=perspective_code,
            check_passed=True,
            details=DcvWebsiteChangeResponseDetails(
                response_url=f"{url_scheme}://{domain_or_ip}/{http_token_path}",
                response_status_code=200
            )
        )
        return request, response

    @staticmethod
    def create_valid_dns_check_request_and_response(perspective_code: str, record_type=DnsRecordType.TXT) -> tuple[DcvCheckRequest, DcvCheckResponse]:
        request = ValidCheckCreator.create_valid_dns_check_request(record_type)
        response = DcvCheckResponse(
            perspective_code=perspective_code,
            check_passed=True,
            details=DcvDnsChangeResponseDetails()
        )
        return request, response
