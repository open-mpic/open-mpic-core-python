from open_mpic_core.common_domain.check_parameters import DcvCheckParameters, DcvWebsiteChangeValidationDetails, \
    DcvDnsChangeValidationDetails, CaaCheckParameters, DcvAcmeHttp01ValidationDetails, DcvAcmeDns01ValidationDetails, \
    DcvIpLookupValidationDetails, DcvContactEmailCaaValidationDetails, DcvContactEmailTxtValidationDetails, \
    DcvContactPhoneCaaValidationDetails, DcvContactPhoneTxtValidationDetails
from open_mpic_core.common_domain.check_request import DcvCheckRequest, CaaCheckRequest
from open_mpic_core.common_domain.enum.certificate_type import CertificateType
from open_mpic_core.common_domain.enum.dcv_validation_method import DcvValidationMethod
from open_mpic_core.common_domain.enum.dns_record_type import DnsRecordType
from open_mpic_core.common_domain.enum.url_scheme import UrlScheme


class ValidCheckCreator:
    @staticmethod
    def create_valid_caa_check_request() -> CaaCheckRequest:
        return CaaCheckRequest(domain_or_ip_target='example.com',
                               caa_check_parameters=CaaCheckParameters(
                                   certificate_type=CertificateType.TLS_SERVER, caa_domains=['ca1.com']
                               ))

    @staticmethod
    def create_valid_http_check_request() -> DcvCheckRequest:
        return DcvCheckRequest(domain_or_ip_target='example.com',
                               dcv_check_parameters=DcvCheckParameters(
                                   validation_details=DcvWebsiteChangeValidationDetails(
                                       http_token_path='token111_ca1.txt',
                                       challenge_value='challenge_111',
                                       url_scheme=UrlScheme.HTTP
                                   )
                               ))

    @staticmethod
    def create_valid_dns_check_request(record_type=DnsRecordType.TXT) -> DcvCheckRequest:
        check_request = DcvCheckRequest(
                            domain_or_ip_target='example.com',
                            dcv_check_parameters=DcvCheckParameters(
                                validation_details=DcvDnsChangeValidationDetails(
                                    dns_name_prefix='_dnsauth',
                                    dns_record_type=record_type,
                                    challenge_value=f"{record_type}_challenge_111.ca1.com."
                                )
                            ))
        check_request.dcv_check_parameters.validation_details.require_exact_match = False
        return check_request

    @staticmethod
    def create_valid_contact_check_request(validation_method: DcvValidationMethod, record_type: DnsRecordType) -> DcvCheckRequest:
        match validation_method:
            case DcvValidationMethod.CONTACT_EMAIL:
                if record_type == DnsRecordType.CAA:
                    validation_details = DcvContactEmailCaaValidationDetails(
                        challenge_value='validate.me@example.com', dns_name_prefix='')
                else:  # DnsRecordType.TXT
                    validation_details = DcvContactEmailTxtValidationDetails(challenge_value=f"validate.me@example.com")
            case _:  # DcvValidationMethod.CONTACT_PHONE
                if record_type == DnsRecordType.CAA:
                    validation_details = DcvContactPhoneCaaValidationDetails(
                        challenge_value='555-555-5555', dns_name_prefix='')
                else:  # DnsRecordType.TXT
                    validation_details = DcvContactPhoneTxtValidationDetails(challenge_value='555-555-5555')
        check_request = DcvCheckRequest(domain_or_ip_target='example.com', dcv_check_parameters=DcvCheckParameters(
                                validation_details=validation_details
                            ))
        check_request.dcv_check_parameters.validation_details.require_exact_match = True
        return check_request

    @staticmethod
    def create_valid_ip_lookup_check_request(record_type=DnsRecordType.A) -> DcvCheckRequest:
        check_request = DcvCheckRequest(
                            domain_or_ip_target='example.com',
                            dcv_check_parameters=DcvCheckParameters(
                                validation_details=DcvIpLookupValidationDetails(
                                    dns_name_prefix='_dnsauth',
                                    dns_record_type=record_type,
                                    challenge_value='CHANGE_ME'
                                )
                            ))
        challenge_value = '192.0.2.1' if record_type == DnsRecordType.A else '2001:db8::1'  # A or AAAA
        check_request.dcv_check_parameters.validation_details.challenge_value = challenge_value
        return check_request

    @staticmethod
    def create_valid_acme_http_01_check_request() -> DcvCheckRequest:
        return DcvCheckRequest(domain_or_ip_target='example.com',
                               dcv_check_parameters=DcvCheckParameters(
                                   validation_details=DcvAcmeHttp01ValidationDetails(
                                       token='token111_ca1',
                                       key_authorization='challenge_111'
                                   )
                               ))

    @staticmethod
    def create_valid_acme_dns_01_check_request():
        return DcvCheckRequest(domain_or_ip_target='example.com',
                               dcv_check_parameters=DcvCheckParameters(
                                   validation_details=DcvAcmeDns01ValidationDetails(
                                       key_authorization='challenge_111'
                                   )
                               ))

    @staticmethod
    def create_valid_dcv_check_request(validation_method: DcvValidationMethod, record_type=DnsRecordType.TXT):
        match validation_method:
            case DcvValidationMethod.WEBSITE_CHANGE_V2:
                return ValidCheckCreator.create_valid_http_check_request()
            case DcvValidationMethod.DNS_CHANGE:
                return ValidCheckCreator.create_valid_dns_check_request(record_type)
            case DcvValidationMethod.ACME_HTTP_01:
                return ValidCheckCreator.create_valid_acme_http_01_check_request()
            case DcvValidationMethod.ACME_DNS_01:
                return ValidCheckCreator.create_valid_acme_dns_01_check_request()
            case DcvValidationMethod.CONTACT_EMAIL | DcvValidationMethod.CONTACT_PHONE:
                return ValidCheckCreator.create_valid_contact_check_request(validation_method, record_type)
