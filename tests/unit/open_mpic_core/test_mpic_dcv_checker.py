import dns
import pytest
from open_mpic_core.common_domain.check_request import DcvCheckRequest
from open_mpic_core.common_domain.check_response import DcvCheckResponse, DcvCheckResponseDetails
from open_mpic_core.common_domain.check_response_details import DcvDnsChangeResponseDetails, \
    DcvWebsiteChangeResponseDetails
from open_mpic_core.common_domain.enum.dcv_validation_method import DcvValidationMethod
from open_mpic_core.common_domain.enum.dns_record_type import DnsRecordType
from open_mpic_core.common_domain.remote_perspective import RemotePerspective
from open_mpic_core.common_domain.validation_error import MpicValidationError
from open_mpic_core.mpic_dcv_checker.mpic_dcv_checker import MpicDcvChecker

from unit.test_util.mock_dns_object_creator import MockDnsObjectCreator
from unit.test_util.valid_check_creator import ValidCheckCreator


# noinspection PyMethodMayBeStatic
class TestMpicDcvChecker:
    @staticmethod
    @pytest.fixture(scope='class')
    def set_env_variables():
        envvars = {
            'default_caa_domains': 'ca1.com|ca2.net|ca3.org',
            'AWS_REGION': 'us-east-4',
            'rir_region': 'arin',
        }
        with pytest.MonkeyPatch.context() as class_scoped_monkeypatch:
            for k, v in envvars.items():
                class_scoped_monkeypatch.setenv(k, v)
            yield class_scoped_monkeypatch  # restore the environment afterward

    @staticmethod
    def create_configured_dcv_checker(rir: str = 'arin', perspective_code: str = 'us-east-4'):
        return MpicDcvChecker(RemotePerspective(rir=rir, code=perspective_code))

    # integration test of a sort -- only mocking dns methods rather than remaining class methods
    @pytest.mark.parametrize('validation_method, record_type', [(DcvValidationMethod.WEBSITE_CHANGE_V2, None),
                                                                (DcvValidationMethod.DNS_CHANGE, DnsRecordType.TXT),
                                                                (DcvValidationMethod.DNS_CHANGE, DnsRecordType.CNAME)])
    def check_dcv__should_perform_appropriate_check_and_allow_issuance_given_target_record_found(self, set_env_variables, validation_method, record_type, mocker):
        dcv_request, response_details, expected_response = None, None, None
        match validation_method:
            case DcvValidationMethod.WEBSITE_CHANGE_V2:
                dcv_request = ValidCheckCreator.create_valid_http_check_request()
                self.mock_website_change_related_calls(dcv_request, mocker)
            case DcvValidationMethod.DNS_CHANGE:
                dcv_request = ValidCheckCreator.create_valid_dns_check_request(record_type)
                self.mock_dns_related_calls(dcv_request, mocker)
        dcv_checker = TestMpicDcvChecker.create_configured_dcv_checker()
        dcv_response = dcv_checker.check_dcv(dcv_request)
        dcv_response.timestamp_ns = None  # ignore timestamp for comparison
        assert dcv_response.check_passed is True

    def perform_website_change_validation__should_return_check_passed_true_with_details_given_request_token_file_found(self, set_env_variables, mocker):
        dcv_request = ValidCheckCreator.create_valid_http_check_request()
        self.mock_website_change_related_calls(dcv_request, mocker)
        dcv_checker = TestMpicDcvChecker.create_configured_dcv_checker()
        dcv_response = dcv_checker.perform_website_change_validation(dcv_request)
        url_scheme = dcv_request.dcv_check_parameters.validation_details.url_scheme
        http_token_path = dcv_request.dcv_check_parameters.validation_details.http_token_path
        expected_response_details = DcvWebsiteChangeResponseDetails(
            response_url=f"{url_scheme}://{dcv_request.domain_or_ip_target}/{MpicDcvChecker.WELL_KNOWN_PKI_PATH}/{http_token_path}",
            response_status_code=200
        )
        assert dcv_response.timestamp_ns is not None
        assert dcv_response.details == expected_response_details

    def perform_website_change_validation__should_return_check_passed_false_with_details_given_request_token_file_not_found(self, set_env_variables, mocker):
        dcv_request = ValidCheckCreator.create_valid_http_check_request()
        mocker.patch('requests.get', return_value=type('Response', (object,), {'status_code': 404, 'reason': 'Not Found'})())
        dcv_checker = TestMpicDcvChecker.create_configured_dcv_checker()
        dcv_response = dcv_checker.perform_website_change_validation(dcv_request)
        assert dcv_response.timestamp_ns is not None
        errors = [MpicValidationError(error_type='404', error_message='Not Found')]
        assert dcv_response.check_passed is False
        assert dcv_response.errors == errors

    def perform_website_change_validation__should_auto_insert_well_known_path_segment(self, set_env_variables, mocker):
        dcv_request = ValidCheckCreator.create_valid_http_check_request()
        dcv_request.dcv_check_parameters.validation_details.http_token_path = 'test-path'
        self.mock_website_change_related_calls(dcv_request, mocker)
        dcv_checker = TestMpicDcvChecker.create_configured_dcv_checker()
        dcv_response = dcv_checker.perform_website_change_validation(dcv_request)
        url_scheme = dcv_request.dcv_check_parameters.validation_details.url_scheme
        expected_url = f"{url_scheme}://{dcv_request.domain_or_ip_target}/.well-known/pki-validation/test-path"
        assert dcv_response.details.response_url == expected_url

    @pytest.mark.parametrize('url_scheme', ['http', 'https'])
    def perform_website_change_validation__should_use_specified_url_scheme(self, set_env_variables, url_scheme, mocker):
        dcv_request = ValidCheckCreator.create_valid_http_check_request()
        dcv_request.dcv_check_parameters.validation_details.url_scheme = url_scheme
        self.mock_website_change_related_calls(dcv_request, mocker)
        dcv_checker = TestMpicDcvChecker.create_configured_dcv_checker()
        dcv_response = dcv_checker.perform_website_change_validation(dcv_request)
        assert dcv_response.check_passed is True
        assert dcv_response.details.response_url.startswith(f"{url_scheme}://")

    @pytest.mark.parametrize('record_type', [DnsRecordType.TXT, DnsRecordType.CNAME])
    def perform_dns_change_validation__should_return_check_passed_true_with_details_given_expected_dns_record_found(self, set_env_variables, record_type, mocker):
        dcv_request = ValidCheckCreator.create_valid_dns_check_request(record_type)
        self.mock_dns_related_calls(dcv_request, mocker)
        expected_response_details = DcvDnsChangeResponseDetails(
            # nothing here yet
        )
        dcv_checker = TestMpicDcvChecker.create_configured_dcv_checker()
        dcv_response = dcv_checker.perform_dns_change_validation(dcv_request)
        assert dcv_response.timestamp_ns is not None
        assert dcv_response.check_passed is True
        assert dcv_response.details == expected_response_details

    def perform_dns_change_validation__should_return_check_passed_false_with_details_given_expected_dns_record_not_found(self, set_env_variables, mocker):
        dcv_request = ValidCheckCreator.create_valid_dns_check_request()
        no_answer_error = dns.resolver.NoAnswer()
        mocker.patch('dns.resolver.resolve', side_effect=lambda domain_name, rdtype: self.raise_(no_answer_error))
        dcv_checker = TestMpicDcvChecker.create_configured_dcv_checker()
        dcv_response = dcv_checker.perform_dns_change_validation(dcv_request)
        errors = [MpicValidationError(error_type=no_answer_error.__class__.__name__, error_message=no_answer_error.msg)]
        assert dcv_response.check_passed is False
        assert dcv_response.errors == errors

    def raise_(self, ex):
        # noinspection PyUnusedLocal
        def _raise(*args, **kwargs):
            raise ex
        return _raise()

    def mock_website_change_related_calls(self, dcv_request: DcvCheckRequest, mocker):
        url_scheme = dcv_request.dcv_check_parameters.validation_details.url_scheme
        http_token_path = dcv_request.dcv_check_parameters.validation_details.http_token_path
        expected_url = f"{url_scheme}://{dcv_request.domain_or_ip_target}/{MpicDcvChecker.WELL_KNOWN_PKI_PATH}/{http_token_path}"
        expected_challenge = dcv_request.dcv_check_parameters.validation_details.challenge_value
        mocker.patch('requests.get', side_effect=lambda url: (
            type('Response', (object,), {'status_code': 200, 'text': expected_challenge})() if url == expected_url else
            type('Response', (object,), {'status_code': 404, 'reason': 'Not Found'})()
        ))

    def mock_dns_related_calls(self, dcv_request: DcvCheckRequest, mocker):
        dcv_details = dcv_request.dcv_check_parameters.validation_details
        expected_domain = f"{dcv_details.dns_name_prefix}.{dcv_request.domain_or_ip_target}"
        record_data = {'value': dcv_details.challenge_value}
        test_dns_query_answer = MockDnsObjectCreator.create_dns_query_answer(dcv_request.domain_or_ip_target,
                                                                             dcv_details.dns_name_prefix,
                                                                             dcv_details.dns_record_type,
                                                                             record_data, mocker)
        mocker.patch('dns.resolver.resolve', side_effect=lambda domain_name, rdtype: (
            test_dns_query_answer if domain_name == expected_domain else self.raise_(dns.resolver.NoAnswer)
        ))


if __name__ == '__main__':
    pytest.main()
