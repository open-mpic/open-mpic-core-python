from open_mpic_core.common_domain.check_parameters import CaaCheckParameters, DcvCheckParameters, \
    DcvDnsChangeValidationDetails, DcvWebsiteChangeValidationDetails, DcvAcmeDns01ValidationDetails, \
    DcvAcmeHttp01ValidationDetails, DcvContactPhoneCaaValidationDetails, DcvContactPhoneTxtValidationDetails, \
    DcvContactEmailTxtValidationDetails, DcvContactEmailCaaValidationDetails
from open_mpic_core.common_domain.enum.certificate_type import CertificateType
from open_mpic_core.common_domain.enum.dcv_validation_method import DcvValidationMethod
from open_mpic_core.common_domain.enum.dns_record_type import DnsRecordType
from open_mpic_core.common_domain.enum.url_scheme import UrlScheme
from open_mpic_core.mpic_coordinator.domain.mpic_request import BaseMpicRequest
from open_mpic_core.common_domain.enum.check_type import CheckType
from open_mpic_core.mpic_coordinator.domain.mpic_request import MpicCaaRequest
from open_mpic_core.mpic_coordinator.domain.mpic_request import MpicDcvRequest
from open_mpic_core.mpic_coordinator.domain.mpic_orchestration_parameters import MpicRequestOrchestrationParameters


class ValidMpicRequestCreator:
    @staticmethod
    def create_valid_caa_mpic_request() -> MpicCaaRequest:
        return MpicCaaRequest(
            domain_or_ip_target='test.example.com',
            orchestration_parameters=MpicRequestOrchestrationParameters(perspective_count=6, quorum_count=4),
            caa_check_parameters=CaaCheckParameters(certificate_type=CertificateType.TLS_SERVER)
        )

    @staticmethod
    def create_valid_dcv_mpic_request(validation_method=DcvValidationMethod.DNS_CHANGE) -> MpicDcvRequest:
        return MpicDcvRequest(
            domain_or_ip_target='test.example.com',
            orchestration_parameters=MpicRequestOrchestrationParameters(perspective_count=6, quorum_count=4),
            dcv_check_parameters=DcvCheckParameters(
                validation_details=ValidMpicRequestCreator.create_validation_details(validation_method)
            )
        )

    @staticmethod
    def create_valid_mpic_request(check_type, validation_method=DcvValidationMethod.DNS_CHANGE) -> BaseMpicRequest:
        match check_type:
            case CheckType.CAA:
                return ValidMpicRequestCreator.create_valid_caa_mpic_request()
            case CheckType.DCV:
                return ValidMpicRequestCreator.create_valid_dcv_mpic_request(validation_method)

    @classmethod
    def create_validation_details(cls, validation_method=DcvValidationMethod.DNS_CHANGE, dns_record_type=DnsRecordType.TXT):
        validation_details = {}
        match validation_method:
            case DcvValidationMethod.DNS_CHANGE:
                validation_details = DcvDnsChangeValidationDetails(dns_name_prefix='test', dns_record_type=dns_record_type, challenge_value='test')
            case DcvValidationMethod.WEBSITE_CHANGE_V2:
                validation_details = DcvWebsiteChangeValidationDetails(
                    http_token_path='examplepath', challenge_value='test', url_scheme=UrlScheme.HTTP)  # noqa E501 (http)
            case DcvValidationMethod.ACME_HTTP_01:
                validation_details = DcvAcmeHttp01ValidationDetails(token='test', key_authorization='test')
            case DcvValidationMethod.ACME_DNS_01:
                validation_details = DcvAcmeDns01ValidationDetails(key_authorization='test')
            case DcvValidationMethod.CONTACT_PHONE:
                if dns_record_type == DnsRecordType.CAA:
                    validation_details = DcvContactPhoneCaaValidationDetails(dns_name_prefix='test', challenge_value='test')
                else:
                    validation_details = DcvContactPhoneTxtValidationDetails(challenge_value='test')
            case DcvValidationMethod.CONTACT_EMAIL:
                if dns_record_type == DnsRecordType.CAA:
                    validation_details = DcvContactEmailCaaValidationDetails(dns_name_prefix='test', challenge_value='test')
                else:
                    validation_details = DcvContactEmailTxtValidationDetails(challenge_value='test')
        return validation_details
