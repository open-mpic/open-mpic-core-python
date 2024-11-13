import base64
from io import BytesIO
from unittest.mock import MagicMock

import dns
import pytest
from dns.rcode import Rcode
from requests import Response, RequestException

from open_mpic_core.common_domain.check_request import DcvCheckRequest
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

    @staticmethod
    def create_mock_response(status_code: int, content: str, kwargs: dict = None):
        response = MagicMock()
        response.status_code = status_code
        response.raw = BytesIO(content.encode('utf-8'))
        response.text = content
        if kwargs is not None:
            for k, v in kwargs.items():
                setattr(response, k, v)
        return response

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
                self.mock_dns_resolve_call(dcv_request, mocker)
        dcv_checker = TestMpicDcvChecker.create_configured_dcv_checker()
        dcv_response = dcv_checker.check_dcv(dcv_request)
        dcv_response.timestamp_ns = None  # ignore timestamp for comparison
        assert dcv_response.check_passed is True

    @pytest.mark.skip('this is just for local debugging...')  # FIXME delete this before long
    def delete_me__this_is_used_for_local_debugging_for_now(self, set_env_variables):
        dcv_request = ValidCheckCreator.create_valid_http_check_request()
        dcv_request.domain_or_ip_target = 'sectigo.com'  # 404: 'https://blog.fluidui.com/moomoomoo'
        dcv_request.dcv_check_parameters.validation_details.url_scheme = 'https'
        dcv_checker = TestMpicDcvChecker.create_configured_dcv_checker()
        dcv_response = dcv_checker.check_dcv(dcv_request)
        assert dcv_response.check_passed is True

    def perform_website_change_validation__should_return_check_success_given_request_token_file_found(self, set_env_variables, mocker):
        dcv_request = ValidCheckCreator.create_valid_http_check_request()
        self.mock_website_change_related_calls(dcv_request, mocker)
        dcv_checker = TestMpicDcvChecker.create_configured_dcv_checker()
        dcv_response = dcv_checker.perform_website_change_validation(dcv_request)
        assert dcv_response.check_passed is True

    def perform_website_change_validation__should_return_timestamp_and_response_url_and_status_code(self, set_env_variables, mocker):
        dcv_request = ValidCheckCreator.create_valid_http_check_request()
        self.mock_website_change_related_calls(dcv_request, mocker)
        dcv_checker = TestMpicDcvChecker.create_configured_dcv_checker()
        dcv_response = dcv_checker.perform_website_change_validation(dcv_request)
        url_scheme = dcv_request.dcv_check_parameters.validation_details.url_scheme
        http_token_path = dcv_request.dcv_check_parameters.validation_details.http_token_path
        assert dcv_response.timestamp_ns is not None
        assert dcv_response.details.response_url == f"{url_scheme}://{dcv_request.domain_or_ip_target}/{MpicDcvChecker.WELL_KNOWN_PKI_PATH}/{http_token_path}"
        assert dcv_response.details.response_status_code == 200

    def perform_website_change_validation__should_return_check_failure_given_request_token_file_not_found(self, set_env_variables, mocker):
        dcv_request = ValidCheckCreator.create_valid_http_check_request()
        fail_response = TestMpicDcvChecker.create_mock_response(404, 'Not Found', {'reason': 'Not Found'})
        mocker.patch('requests.get', return_value=fail_response)
        dcv_checker = TestMpicDcvChecker.create_configured_dcv_checker()
        dcv_response = dcv_checker.perform_website_change_validation(dcv_request)
        assert dcv_response.check_passed is False

    def perform_website_change_validation__should_return_error_details_given_request_token_file_not_found(self, set_env_variables, mocker):
        dcv_request = ValidCheckCreator.create_valid_http_check_request()
        fail_response = TestMpicDcvChecker.create_mock_response(404, 'Not Found', {'reason': 'Not Found'})
        mocker.patch('requests.get', return_value=fail_response)
        dcv_checker = TestMpicDcvChecker.create_configured_dcv_checker()
        dcv_response = dcv_checker.perform_website_change_validation(dcv_request)
        assert dcv_response.check_passed is False
        assert dcv_response.timestamp_ns is not None
        errors = [MpicValidationError(error_type='404', error_message='Not Found')]
        assert dcv_response.errors == errors

    def perform_website_change_validation__should_return_check_failure_and_error_details_given_exception_raised(self, set_env_variables, mocker):
        dcv_request = ValidCheckCreator.create_valid_http_check_request()
        mocker.patch('requests.get', side_effect=lambda url, stream: self.raise_(RequestException('Test Exception')))
        dcv_checker = TestMpicDcvChecker.create_configured_dcv_checker()
        dcv_response = dcv_checker.perform_website_change_validation(dcv_request)
        assert dcv_response.check_passed is False
        errors = [MpicValidationError(error_type='RequestException', error_message='Test Exception')]
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

    def perform_website_change_validation__should_follow_redirects_and_track_redirect_history_in_details(self, set_env_variables, mocker):
        dcv_request = ValidCheckCreator.create_valid_http_check_request()
        self.mock_website_change_http_call_with_redirects(dcv_request, mocker)
        dcv_checker = TestMpicDcvChecker.create_configured_dcv_checker()
        dcv_response = dcv_checker.perform_website_change_validation(dcv_request)
        redirects = dcv_response.details.response_history
        assert len(redirects) == 2
        assert redirects[0].url == 'https://example.com/redirected-1'
        assert redirects[0].status_code == 301
        assert redirects[1].url == 'https://example.com/redirected-2'
        assert redirects[1].status_code == 302

    @pytest.mark.parametrize('url_scheme', ['http', 'https'])
    def perform_website_change_validation__should_use_specified_url_scheme(self, set_env_variables, url_scheme, mocker):
        dcv_request = ValidCheckCreator.create_valid_http_check_request()
        dcv_request.dcv_check_parameters.validation_details.url_scheme = url_scheme
        self.mock_website_change_related_calls(dcv_request, mocker)
        dcv_checker = TestMpicDcvChecker.create_configured_dcv_checker()
        dcv_response = dcv_checker.perform_website_change_validation(dcv_request)
        assert dcv_response.check_passed is True
        assert dcv_response.details.response_url.startswith(f"{url_scheme}://")

    def perform_website_change_validation__should_include_up_to_first_100_bytes_of_returned_content_in_details(self, set_env_variables, mocker):
        dcv_request = ValidCheckCreator.create_valid_http_check_request()
        self.mock_website_change_validation_large_payload(mocker)
        dcv_checker = TestMpicDcvChecker.create_configured_dcv_checker()
        dcv_response = dcv_checker.perform_website_change_validation(dcv_request)
        hundred_a_chars = b'a' * 100  # store 100 'a' characters in a byte array
        expected_content = base64.b64encode(hundred_a_chars)  # is this correct?
        assert dcv_response.details.response_page == expected_content

    @pytest.mark.parametrize('record_type', [DnsRecordType.TXT, DnsRecordType.CNAME])
    def perform_dns_change_validation__should_return_check_success_given_expected_dns_record_found(self, set_env_variables, record_type, mocker):
        dcv_request = ValidCheckCreator.create_valid_dns_check_request(record_type)
        self.mock_dns_resolve_call(dcv_request, mocker)
        dcv_checker = TestMpicDcvChecker.create_configured_dcv_checker()
        dcv_response = dcv_checker.perform_dns_change_validation(dcv_request)
        assert dcv_response.check_passed is True

    def perform_dns_change_validation__should_return_timestamp_and_list_of_records_seen(self, set_env_variables, mocker):
        dcv_request = ValidCheckCreator.create_valid_dns_check_request(DnsRecordType.TXT)  # must specify TXT here
        self.mock_dns_resolve_call_getting_multiple_txt_records(dcv_request, mocker)
        dcv_checker = TestMpicDcvChecker.create_configured_dcv_checker()
        dcv_response = dcv_checker.perform_dns_change_validation(dcv_request)
        assert dcv_response.timestamp_ns is not None
        expected_value_1 = dcv_request.dcv_check_parameters.validation_details.challenge_value
        expected_records = [expected_value_1, 'whatever2', 'whatever3']
        assert dcv_response.details.records_seen == expected_records

    @pytest.mark.parametrize('response_code', [Rcode.NOERROR, Rcode.NXDOMAIN, Rcode.REFUSED])
    def perform_dns_change_validation__should_return_response_code(self, set_env_variables, response_code, mocker):
        dcv_request = ValidCheckCreator.create_valid_dns_check_request()
        self.mock_dns_resolve_call_to_return_specific_response_code(dcv_request, response_code, mocker)
        dcv_checker = TestMpicDcvChecker.create_configured_dcv_checker()
        dcv_response = dcv_checker.perform_dns_change_validation(dcv_request)
        assert dcv_response.details.response_code == response_code

    def perform_dns_change_validation__should_return_check_failure_with_errors_given_expected_dns_record_not_found(self, set_env_variables, mocker):
        dcv_request = ValidCheckCreator.create_valid_dns_check_request()
        no_answer_error = dns.resolver.NoAnswer()
        mocker.patch('dns.resolver.resolve', side_effect=lambda domain_name, rdtype: self.raise_(no_answer_error))
        dcv_checker = TestMpicDcvChecker.create_configured_dcv_checker()
        dcv_response = dcv_checker.perform_dns_change_validation(dcv_request)
        errors = [MpicValidationError(error_type=no_answer_error.__class__.__name__, error_message=no_answer_error.msg)]
        assert dcv_response.check_passed is False
        assert dcv_response.errors == errors

    @pytest.mark.skip(reason='Not yet implemented')
    def perform_acme_http_validation__should_return_check_passed_true_with_details_given_expected_response(self, set_env_variables, mocker):
        pass

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
        success_response = TestMpicDcvChecker.create_mock_response(200, expected_challenge)
        mocker.patch('requests.get', side_effect=lambda url, stream: (
            success_response if url == expected_url else
            TestMpicDcvChecker.create_mock_response(404, 'Not Found', {'reason': 'Not Found'})
        ))

    # TODO use this to test 100 bytes in details...
    def mock_website_change_validation_large_payload(self, mocker):
        response = Response()
        response.status_code = 200
        response.raw = BytesIO(b'a' * 1000)
        mocker.patch('requests.get', side_effect=lambda url, stream: (
            response
        ))

    def mock_dns_resolve_call(self, dcv_request: DcvCheckRequest, mocker):
        dcv_details = dcv_request.dcv_check_parameters.validation_details
        expected_domain = f"{dcv_details.dns_name_prefix}.{dcv_request.domain_or_ip_target}"
        record_data = {'value': dcv_details.challenge_value}
        test_dns_query_answer = MockDnsObjectCreator.create_dns_query_answer(
            dcv_request.domain_or_ip_target, dcv_details.dns_name_prefix, dcv_details.dns_record_type, record_data, mocker
        )
        mocker.patch('dns.resolver.resolve', side_effect=lambda domain_name, rdtype: (
            test_dns_query_answer if domain_name == expected_domain else self.raise_(dns.resolver.NoAnswer)
        ))

    def mock_dns_resolve_call_to_return_specific_response_code(self, dcv_request: DcvCheckRequest, response_code, mocker):
        dcv_details = dcv_request.dcv_check_parameters.validation_details
        expected_domain = f"{dcv_details.dns_name_prefix}.{dcv_request.domain_or_ip_target}"
        record_data = {'value': dcv_details.challenge_value}
        test_dns_query_answer = MockDnsObjectCreator.create_dns_query_answer(
            dcv_request.domain_or_ip_target, dcv_details.dns_name_prefix, dcv_details.dns_record_type, record_data, mocker
        )
        test_dns_query_answer.response.rcode = response_code
        mocker.patch('dns.resolver.resolve', side_effect=lambda domain_name, rdtype: (
            test_dns_query_answer if domain_name == expected_domain else self.raise_(dns.resolver.NoAnswer)
        ))

    def mock_dns_resolve_call_getting_multiple_txt_records(self, dcv_request: DcvCheckRequest, mocker):
        dcv_details = dcv_request.dcv_check_parameters.validation_details
        expected_domain = f"{dcv_details.dns_name_prefix}.{dcv_request.domain_or_ip_target}"
        record_data = {'value': dcv_details.challenge_value}
        txt_record_1 = MockDnsObjectCreator.create_record_by_type(DnsRecordType.TXT, record_data)
        txt_record_2 = MockDnsObjectCreator.create_record_by_type(DnsRecordType.TXT, {'value': 'whatever2'})
        txt_record_3 = MockDnsObjectCreator.create_record_by_type(DnsRecordType.TXT, {'value': 'whatever3'})
        test_dns_query_answer = MockDnsObjectCreator.create_dns_query_answer_with_multiple_txt_records(
            dcv_request.domain_or_ip_target, dcv_details.dns_name_prefix,
            *[txt_record_1, txt_record_2, txt_record_3], mocker=mocker
        )
        mocker.patch('dns.resolver.resolve', side_effect=lambda domain_name, rdtype: (
            test_dns_query_answer if domain_name == expected_domain else self.raise_(dns.resolver.NoAnswer)
        ))

    def mock_website_change_http_call_with_redirects(self, dcv_request: DcvCheckRequest, mocker):
        url_scheme = dcv_request.dcv_check_parameters.validation_details.url_scheme
        http_token_path = dcv_request.dcv_check_parameters.validation_details.http_token_path
        expected_url = f"{url_scheme}://{dcv_request.domain_or_ip_target}/{MpicDcvChecker.WELL_KNOWN_PKI_PATH}/{http_token_path}"
        expected_challenge = dcv_request.dcv_check_parameters.validation_details.challenge_value
        redirect_url_1 = f"https://example.com/redirected-1"
        redirect_response_1 = Response()
        redirect_response_1.status_code = 301
        redirect_response_1.headers['Location'] = redirect_url_1
        redirect_url_2 = f"https://example.com/redirected-2"
        redirect_response_2 = Response()
        redirect_response_2.status_code = 302
        redirect_response_2.headers['Location'] = redirect_url_2
        history = [redirect_response_1, redirect_response_2]
        mocker.patch('requests.get', side_effect=lambda url, stream: (
            TestMpicDcvChecker.create_mock_response(200, expected_challenge, {'history': history}) if url == expected_url else
            TestMpicDcvChecker.create_mock_response(404, 'Not Found', {'reason': 'Not Found'})
        ))


if __name__ == '__main__':
    pytest.main()
