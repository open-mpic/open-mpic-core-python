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
                                                                (DcvValidationMethod.DNS_CHANGE, DnsRecordType.CNAME),
                                                                (DcvValidationMethod.ACME_HTTP_01, None),
                                                                (DcvValidationMethod.ACME_DNS_01, None)])
    def check_dcv__should_perform_appropriate_check_and_allow_issuance_given_target_record_found(self, set_env_variables, validation_method, record_type, mocker):
        match validation_method:
            case DcvValidationMethod.WEBSITE_CHANGE_V2:
                dcv_request = ValidCheckCreator.create_valid_dcv_check_request(validation_method)
                self.mock_http_call_response(dcv_request, mocker)
            case DcvValidationMethod.DNS_CHANGE:
                dcv_request = ValidCheckCreator.create_valid_dns_check_request(record_type)
                self.mock_dns_resolve_call(dcv_request, mocker)
            case DcvValidationMethod.ACME_HTTP_01:
                dcv_request = ValidCheckCreator.create_valid_dcv_check_request(validation_method)
                self.mock_http_call_response(dcv_request, mocker)
            case _:
                dcv_request = ValidCheckCreator.create_valid_dcv_check_request(validation_method)
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

    @pytest.mark.parametrize('validation_method', [DcvValidationMethod.WEBSITE_CHANGE_V2, DcvValidationMethod.ACME_HTTP_01])
    def http_based_dcv_checks__should_return_check_success_given_token_file_found_with_expected_content(self, set_env_variables, validation_method, mocker):
        dcv_checker = TestMpicDcvChecker.create_configured_dcv_checker()
        dcv_request = ValidCheckCreator.create_valid_dcv_check_request(validation_method)
        self.mock_http_call_response(dcv_request, mocker)
        dcv_response = dcv_checker.check_dcv(dcv_request)
        assert dcv_response.check_passed is True

    @pytest.mark.parametrize('validation_method', [DcvValidationMethod.WEBSITE_CHANGE_V2, DcvValidationMethod.ACME_HTTP_01])
    def http_based_dcv_checks__should_return_timestamp_and_response_url_and_status_code(self, set_env_variables, validation_method, mocker):
        dcv_checker = TestMpicDcvChecker.create_configured_dcv_checker()
        dcv_request = ValidCheckCreator.create_valid_dcv_check_request(validation_method)
        self.mock_http_call_response(dcv_request, mocker)
        dcv_response = dcv_checker.check_dcv(dcv_request)
        match validation_method:
            case DcvValidationMethod.WEBSITE_CHANGE_V2:
                url_scheme = dcv_request.dcv_check_parameters.validation_details.url_scheme
                http_token_path = dcv_request.dcv_check_parameters.validation_details.http_token_path
                expected_url = f"{url_scheme}://{dcv_request.domain_or_ip_target}/{MpicDcvChecker.WELL_KNOWN_PKI_PATH}/{http_token_path}"
            case _:
                token = dcv_request.dcv_check_parameters.validation_details.token
                expected_url = f"http://{dcv_request.domain_or_ip_target}/{MpicDcvChecker.WELL_KNOWN_ACME_PATH}/{token}"  # noqa E501 (http)
        assert dcv_response.timestamp_ns is not None
        assert dcv_response.details.response_url == expected_url
        assert dcv_response.details.response_status_code == 200

    @pytest.mark.parametrize('validation_method', [DcvValidationMethod.WEBSITE_CHANGE_V2, DcvValidationMethod.ACME_HTTP_01])
    def http_based_dcv_checks__should_return_check_failure_given_token_file_not_found(self, set_env_variables, validation_method, mocker):
        fail_response = TestMpicDcvChecker.create_mock_response(404, 'Not Found', {'reason': 'Not Found'})
        mocker.patch('requests.get', return_value=fail_response)
        dcv_checker = TestMpicDcvChecker.create_configured_dcv_checker()
        dcv_request = ValidCheckCreator.create_valid_dcv_check_request(validation_method)
        dcv_response = dcv_checker.check_dcv(dcv_request)
        assert dcv_response.check_passed is False

    @pytest.mark.parametrize('validation_method', [DcvValidationMethod.WEBSITE_CHANGE_V2, DcvValidationMethod.ACME_HTTP_01])
    def http_based_dcv_checks__should_return_error_details_given_token_file_not_found(self, set_env_variables, validation_method, mocker):
        fail_response = TestMpicDcvChecker.create_mock_response(404, 'Not Found', {'reason': 'Not Found'})
        mocker.patch('requests.get', return_value=fail_response)
        dcv_checker = TestMpicDcvChecker.create_configured_dcv_checker()
        dcv_request = ValidCheckCreator.create_valid_dcv_check_request(validation_method)
        dcv_response = dcv_checker.check_dcv(dcv_request)
        assert dcv_response.check_passed is False
        assert dcv_response.timestamp_ns is not None
        errors = [MpicValidationError(error_type='404', error_message='Not Found')]
        assert dcv_response.errors == errors

    @pytest.mark.parametrize('validation_method', [DcvValidationMethod.WEBSITE_CHANGE_V2, DcvValidationMethod.ACME_HTTP_01])
    def http_based_dcv_checks__should_return_check_failure_and_error_details_given_exception_raised(self, set_env_variables, validation_method, mocker):
        dcv_checker = TestMpicDcvChecker.create_configured_dcv_checker()
        mocker.patch('requests.get', side_effect=lambda *args, **kwargs: self.raise_(RequestException('Test Exception')))
        dcv_request = ValidCheckCreator.create_valid_dcv_check_request(validation_method)
        dcv_response = dcv_checker.check_dcv(dcv_request)
        assert dcv_response.check_passed is False
        errors = [MpicValidationError(error_type='RequestException', error_message='Test Exception')]
        assert dcv_response.errors == errors

    @pytest.mark.parametrize('validation_method', [DcvValidationMethod.WEBSITE_CHANGE_V2, DcvValidationMethod.ACME_HTTP_01])
    def http_based_dcv_checks__should_return_check_failure_given_non_matching_response_content(self, set_env_variables, validation_method, mocker):
        dcv_checker = TestMpicDcvChecker.create_configured_dcv_checker()
        dcv_request = ValidCheckCreator.create_valid_dcv_check_request(validation_method)
        self.mock_http_call_response(dcv_request, mocker)
        if validation_method == DcvValidationMethod.WEBSITE_CHANGE_V2:
            dcv_request.dcv_check_parameters.validation_details.challenge_value = 'expecting-this-value-now-instead'
        else:
            dcv_request.dcv_check_parameters.validation_details.key_authorization = 'expecting-this-value-now-instead'
        dcv_response = dcv_checker.check_dcv(dcv_request)
        assert dcv_response.check_passed is False

    @pytest.mark.parametrize('validation_method, expected_segment', [
        (DcvValidationMethod.WEBSITE_CHANGE_V2, '.well-known/pki-validation'),
        (DcvValidationMethod.ACME_HTTP_01, '.well-known/acme-challenge')
    ])
    def http_based_dcv_checks__should_auto_insert_well_known_path_segment(self, set_env_variables, validation_method, expected_segment, mocker):
        dcv_checker = TestMpicDcvChecker.create_configured_dcv_checker()
        dcv_request = ValidCheckCreator.create_valid_dcv_check_request(validation_method)
        match validation_method:
            case DcvValidationMethod.WEBSITE_CHANGE_V2:
                dcv_request.dcv_check_parameters.validation_details.http_token_path = 'test-path'
                url_scheme = dcv_request.dcv_check_parameters.validation_details.url_scheme
            case _:
                dcv_request.dcv_check_parameters.validation_details.token = 'test-path'
                url_scheme = 'http'
        self.mock_http_call_response(dcv_request, mocker)
        dcv_response = dcv_checker.check_dcv(dcv_request)
        expected_url = f"{url_scheme}://{dcv_request.domain_or_ip_target}/{expected_segment}/test-path"
        assert dcv_response.details.response_url == expected_url

    @pytest.mark.parametrize('validation_method', [DcvValidationMethod.WEBSITE_CHANGE_V2, DcvValidationMethod.ACME_HTTP_01])
    def http_based_dcv_checks__should_follow_redirects_and_track_redirect_history_in_details(self, set_env_variables, validation_method, mocker):
        dcv_checker = TestMpicDcvChecker.create_configured_dcv_checker()
        dcv_request = ValidCheckCreator.create_valid_dcv_check_request(validation_method)
        self.mock_http_call_response_with_redirects(dcv_request, mocker)
        dcv_response = dcv_checker.check_dcv(dcv_request)
        redirects = dcv_response.details.response_history
        assert len(redirects) == 2
        assert redirects[0].url == 'https://example.com/redirected-1'
        assert redirects[0].status_code == 301
        assert redirects[1].url == 'https://example.com/redirected-2'
        assert redirects[1].status_code == 302

    @pytest.mark.parametrize('validation_method', [DcvValidationMethod.WEBSITE_CHANGE_V2, DcvValidationMethod.ACME_HTTP_01])
    def http_based_dcv_checks__should_include_up_to_first_100_bytes_of_returned_content_in_details(self, set_env_variables, validation_method, mocker):
        dcv_checker = TestMpicDcvChecker.create_configured_dcv_checker()
        dcv_request = ValidCheckCreator.create_valid_dcv_check_request(validation_method)
        self.mock_website_change_validation_large_payload(mocker)
        dcv_response = dcv_checker.check_dcv(dcv_request)
        hundred_a_chars = b'a' * 100  # store 100 'a' characters in a byte array
        assert dcv_response.details.response_page == hundred_a_chars

    @pytest.mark.parametrize('url_scheme', ['http', 'https'])
    def website_change_v2_validation__should_use_specified_url_scheme(self, set_env_variables, url_scheme, mocker):
        dcv_request = ValidCheckCreator.create_valid_http_check_request()
        dcv_request.dcv_check_parameters.validation_details.url_scheme = url_scheme
        self.mock_http_call_response(dcv_request, mocker)
        dcv_checker = TestMpicDcvChecker.create_configured_dcv_checker()
        dcv_response = dcv_checker.perform_website_change_validation(dcv_request)
        assert dcv_response.check_passed is True
        assert dcv_response.details.response_url.startswith(f"{url_scheme}://")

    @pytest.mark.parametrize('record_type', [DnsRecordType.TXT, DnsRecordType.CNAME])
    def dns_change_validation__should_return_check_success_given_expected_dns_record_found(self, set_env_variables, record_type, mocker):
        dcv_request = ValidCheckCreator.create_valid_dns_check_request(record_type)
        self.mock_dns_resolve_call(dcv_request, mocker)
        dcv_checker = TestMpicDcvChecker.create_configured_dcv_checker()
        dcv_response = dcv_checker.perform_dns_change_validation(dcv_request)
        assert dcv_response.check_passed is True

    def acme_dns_validation__should_return_check_success_given_expected_dns_record_found(self, set_env_variables, mocker):
        dcv_request = ValidCheckCreator.create_valid_acme_dns_01_check_request()
        self.mock_dns_resolve_call(dcv_request, mocker)
        dcv_checker = TestMpicDcvChecker.create_configured_dcv_checker()
        dcv_response = dcv_checker.perform_acme_dns_01_validation(dcv_request)
        assert dcv_response.check_passed is True

    @pytest.mark.parametrize('validation_method', [DcvValidationMethod.DNS_CHANGE, DcvValidationMethod.ACME_DNS_01])
    def dns_based_dcv_checks__should_return_check_failure_given_non_matching_dns_record(self, set_env_variables, validation_method, mocker):
        dcv_checker = TestMpicDcvChecker.create_configured_dcv_checker()
        dcv_request = ValidCheckCreator.create_valid_dcv_check_request(validation_method)
        self.mock_dns_resolve_call_with_non_matching_record(dcv_request, mocker)
        dcv_response = dcv_checker.check_dcv(dcv_request)
        assert dcv_response.check_passed is False

    @pytest.mark.parametrize('validation_method', [DcvValidationMethod.DNS_CHANGE, DcvValidationMethod.ACME_DNS_01])
    def dns_based_dcv_checks__should_return_timestamp_and_list_of_records_seen(self, set_env_variables, validation_method, mocker):
        dcv_checker = TestMpicDcvChecker.create_configured_dcv_checker()
        dcv_request = ValidCheckCreator.create_valid_dcv_check_request(validation_method)
        self.mock_dns_resolve_call_getting_multiple_txt_records(dcv_request, mocker)
        dcv_response = dcv_checker.check_dcv(dcv_request)
        if validation_method == DcvValidationMethod.DNS_CHANGE:
            expected_value_1 = dcv_request.dcv_check_parameters.validation_details.challenge_value
        else:
            expected_value_1 = dcv_request.dcv_check_parameters.validation_details.key_authorization
        assert dcv_response.timestamp_ns is not None
        expected_records = [expected_value_1, 'whatever2', 'whatever3']
        assert dcv_response.details.records_seen == expected_records

    @pytest.mark.parametrize('validation_method, response_code', [
        (DcvValidationMethod.DNS_CHANGE, Rcode.NOERROR),
        (DcvValidationMethod.ACME_DNS_01, Rcode.NXDOMAIN),
        (DcvValidationMethod.DNS_CHANGE, Rcode.REFUSED)
    ])
    def dns_based_dcv_checks__should_return_response_code(self, set_env_variables, validation_method, response_code, mocker):
        dcv_checker = TestMpicDcvChecker.create_configured_dcv_checker()
        dcv_request = ValidCheckCreator.create_valid_dcv_check_request(validation_method)
        self.mock_dns_resolve_call_with_specific_response_code(dcv_request, response_code, mocker)
        dcv_response = dcv_checker.check_dcv(dcv_request)
        assert dcv_response.details.response_code == response_code

    @pytest.mark.parametrize('validation_method, flag, flag_set', [
        (DcvValidationMethod.DNS_CHANGE, dns.flags.AD, True),
        (DcvValidationMethod.DNS_CHANGE, dns.flags.CD, False),
        (DcvValidationMethod.ACME_DNS_01, dns.flags.AD, True),
        (DcvValidationMethod.ACME_DNS_01, dns.flags.CD, False)
    ])
    def dns_based_dcv_checks__should_return_whether_response_has_ad_flag(self, validation_method, flag, flag_set, set_env_variables, mocker):
        dcv_checker = TestMpicDcvChecker.create_configured_dcv_checker()
        dcv_request = ValidCheckCreator.create_valid_dcv_check_request(validation_method)
        self.mock_dns_resolve_call_with_specific_flag(dcv_request, flag, mocker)
        dcv_response = dcv_checker.check_dcv(dcv_request)
        assert dcv_response.details.ad_flag is flag_set

    @pytest.mark.parametrize('validation_method', [DcvValidationMethod.DNS_CHANGE, DcvValidationMethod.ACME_DNS_01])
    def dns_based_dcv_checks__should_return_check_failure_with_errors_given_exception_raised(self, set_env_variables, validation_method, mocker):
        dcv_request = ValidCheckCreator.create_valid_dcv_check_request(validation_method)
        no_answer_error = dns.resolver.NoAnswer()
        mocker.patch('dns.resolver.resolve', side_effect=lambda domain_name, rdtype: self.raise_(no_answer_error))
        dcv_checker = TestMpicDcvChecker.create_configured_dcv_checker()
        dcv_response = dcv_checker.check_dcv(dcv_request)
        errors = [MpicValidationError(error_type=no_answer_error.__class__.__name__, error_message=no_answer_error.msg)]
        assert dcv_response.check_passed is False
        assert dcv_response.errors == errors

    def raise_(self, ex):
        # noinspection PyUnusedLocal
        def _raise(*args, **kwargs):
            raise ex
        return _raise()

    def mock_http_call_response(self, dcv_request: DcvCheckRequest, mocker):
        match dcv_request.dcv_check_parameters.validation_details.validation_method:
            case DcvValidationMethod.WEBSITE_CHANGE_V2:
                url_scheme = dcv_request.dcv_check_parameters.validation_details.url_scheme
                http_token_path = dcv_request.dcv_check_parameters.validation_details.http_token_path
                expected_url = f"{url_scheme}://{dcv_request.domain_or_ip_target}/{MpicDcvChecker.WELL_KNOWN_PKI_PATH}/{http_token_path}"
                expected_challenge = dcv_request.dcv_check_parameters.validation_details.challenge_value
            case _:
                token = dcv_request.dcv_check_parameters.validation_details.token
                expected_url = f"http://{dcv_request.domain_or_ip_target}/{MpicDcvChecker.WELL_KNOWN_ACME_PATH}/{token}"  # noqa E501 (http)
                expected_challenge = dcv_request.dcv_check_parameters.validation_details.key_authorization
        success_response = TestMpicDcvChecker.create_mock_response(200, expected_challenge)
        mocker.patch('requests.get', side_effect=lambda *args, **kwargs: (
            success_response if kwargs.get('url') == expected_url else
            TestMpicDcvChecker.create_mock_response(404, 'Not Found', {'reason': 'Not Found'})
        ))

    def mock_website_change_validation_large_payload(self, mocker):
        response = Response()
        response.status_code = 200
        response.raw = BytesIO(b'a' * 1000)
        mocker.patch('requests.get', side_effect=lambda *args, **kwargs: (
            response
        ))

    def mock_http_call_response_with_redirects(self, dcv_request: DcvCheckRequest, mocker):
        match dcv_request.dcv_check_parameters.validation_details.validation_method:
            case DcvValidationMethod.WEBSITE_CHANGE_V2:
                expected_challenge = dcv_request.dcv_check_parameters.validation_details.challenge_value
            case _:
                expected_challenge = dcv_request.dcv_check_parameters.validation_details.key_authorization
        history = self.create_http_redirect_history()
        mocker.patch('requests.get', side_effect=lambda *args, **kwargs: (
            TestMpicDcvChecker.create_mock_response(200, expected_challenge, {'history': history})
        ))

    def mock_dns_resolve_call(self, dcv_request: DcvCheckRequest, mocker):
        match dcv_request.dcv_check_parameters.validation_details.validation_method:
            case DcvValidationMethod.DNS_CHANGE:
                expected_domain = f"{dcv_request.dcv_check_parameters.validation_details.dns_name_prefix}.{dcv_request.domain_or_ip_target}"
            case _:
                expected_domain = f"_acme-challenge.{dcv_request.domain_or_ip_target}"
        test_dns_query_answer = self.create_basic_dns_response_for_mock(dcv_request, mocker)
        mocker.patch('dns.resolver.resolve', side_effect=lambda domain_name, rdtype: (
            test_dns_query_answer if domain_name == expected_domain else self.raise_(dns.resolver.NoAnswer)
        ))

    def mock_dns_resolve_call_with_non_matching_record(self, dcv_request: DcvCheckRequest, mocker):
        test_dns_query_answer = self.create_basic_dns_response_for_mock(dcv_request, mocker)
        test_dns_query_answer.response.answer[0].items.clear()
        test_dns_query_answer.response.answer[0].add(
            MockDnsObjectCreator.create_record_by_type(DnsRecordType.TXT, {'value': 'not-the-expected-value'})
        )
        mocker.patch('dns.resolver.resolve', side_effect=lambda domain_name, rdtype: test_dns_query_answer)

    def mock_dns_resolve_call_with_specific_response_code(self, dcv_request: DcvCheckRequest, response_code, mocker):
        test_dns_query_answer = self.create_basic_dns_response_for_mock(dcv_request, mocker)
        test_dns_query_answer.response.rcode = response_code
        mocker.patch('dns.resolver.resolve', side_effect=lambda domain_name, rdtype: test_dns_query_answer)

    def mock_dns_resolve_call_with_specific_flag(self, dcv_request: DcvCheckRequest, flag, mocker):
        test_dns_query_answer = self.create_basic_dns_response_for_mock(dcv_request, mocker)
        test_dns_query_answer.response.flags |= flag
        mocker.patch('dns.resolver.resolve', side_effect=lambda domain_name, rdtype: test_dns_query_answer)

    def mock_dns_resolve_call_getting_multiple_txt_records(self, dcv_request: DcvCheckRequest, mocker):
        dcv_details = dcv_request.dcv_check_parameters.validation_details
        match dcv_request.dcv_check_parameters.validation_details.validation_method:
            case DcvValidationMethod.DNS_CHANGE:
                record_data = {'value': dcv_details.challenge_value}
                record_name_prefix = dcv_details.dns_name_prefix
            case _:
                record_data = {'value': dcv_details.key_authorization}
                record_name_prefix = '_acme-challenge'
        txt_record_1 = MockDnsObjectCreator.create_record_by_type(DnsRecordType.TXT, record_data)
        txt_record_2 = MockDnsObjectCreator.create_record_by_type(DnsRecordType.TXT, {'value': 'whatever2'})
        txt_record_3 = MockDnsObjectCreator.create_record_by_type(DnsRecordType.TXT, {'value': 'whatever3'})
        test_dns_query_answer = MockDnsObjectCreator.create_dns_query_answer_with_multiple_txt_records(
            dcv_request.domain_or_ip_target, record_name_prefix,
            *[txt_record_1, txt_record_2, txt_record_3], mocker=mocker
        )
        mocker.patch('dns.resolver.resolve', side_effect=lambda domain_name, rdtype: test_dns_query_answer)

    def create_basic_dns_response_for_mock(self, dcv_request: DcvCheckRequest, mocker) -> dns.resolver.Answer:
        dcv_details = dcv_request.dcv_check_parameters.validation_details
        match dcv_request.dcv_check_parameters.validation_details.validation_method:
            case DcvValidationMethod.DNS_CHANGE:
                record_data = {'value': dcv_details.challenge_value}
                record_prefix = dcv_details.dns_name_prefix
                record_type = dcv_details.dns_record_type
            case _:  # ACME_DNS_01
                record_data = {'value': dcv_details.key_authorization}
                record_prefix = '_acme-challenge'
                record_type = DnsRecordType.TXT
        test_dns_query_answer = MockDnsObjectCreator.create_dns_query_answer(
            dcv_request.domain_or_ip_target, record_prefix, record_type, record_data, mocker
        )
        return test_dns_query_answer

    def create_http_redirect_history(self):
        redirect_url_1 = f"https://example.com/redirected-1"
        redirect_response_1 = Response()
        redirect_response_1.status_code = 301
        redirect_response_1.headers['Location'] = redirect_url_1
        redirect_url_2 = f"https://example.com/redirected-2"
        redirect_response_2 = Response()
        redirect_response_2.status_code = 302
        redirect_response_2.headers['Location'] = redirect_url_2
        return [redirect_response_1, redirect_response_2]


if __name__ == '__main__':
    pytest.main()
