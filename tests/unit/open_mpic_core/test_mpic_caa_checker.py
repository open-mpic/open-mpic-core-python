import dns
import pytest

from unittest.mock import AsyncMock

from open_mpic_core.common_domain.check_parameters import CaaCheckParameters
from open_mpic_core.common_domain.check_request import CaaCheckRequest
from open_mpic_core.common_domain.check_response import CaaCheckResponse, CaaCheckResponseDetails
from open_mpic_core.common_domain.enum.certificate_type import CertificateType
from open_mpic_core.common_domain.enum.dns_record_type import DnsRecordType
from open_mpic_core.common_domain.validation_error import MpicValidationError
from open_mpic_core.common_domain.messages.ErrorMessages import ErrorMessages
from open_mpic_core.mpic_caa_checker.mpic_caa_checker import MpicCaaChecker

from unit.test_util.mock_dns_object_creator import MockDnsObjectCreator


# noinspection PyMethodMayBeStatic
class TestMpicCaaChecker:
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
    def create_configured_caa_checker():
        return MpicCaaChecker(["ca1.com", "ca2.net", "ca3.org"], 'us-east-4')

    # integration test of a sort -- only mocking dns methods rather than remaining class methods
    async def check_caa__should_allow_issuance_given_no_caa_records_found(self, set_env_variables, mocker):
        self.patch_resolver_with_answer_or_exception(mocker, dns.resolver.NoAnswer())
        caa_request = CaaCheckRequest(domain_or_ip_target='example.com',
                                      caa_check_parameters=CaaCheckParameters(certificate_type=CertificateType.TLS_SERVER, caa_domains=['ca111.com']))
        caa_checker = TestMpicCaaChecker.create_configured_caa_checker()
        caa_response = await caa_checker.check_caa(caa_request)
        check_response_details = CaaCheckResponseDetails(caa_record_present=False)
        assert self.is_result_as_expected(caa_response, True, check_response_details) is True

    async def check_caa__should_allow_issuance_given_matching_caa_record_found(self, set_env_variables, mocker):
        record_name, expected_domain = 'example.com', 'example.com.'
        test_dns_query_answer = MockDnsObjectCreator.create_caa_query_answer(record_name, 0, 'issue', 'ca111.com', mocker)
        self.patch_resolver_with_conditional_answer_and_exception(mocker, expected_domain, test_dns_query_answer, dns.resolver.NoAnswer)

        caa_request = CaaCheckRequest(domain_or_ip_target='example.com',
                                      caa_check_parameters=CaaCheckParameters(certificate_type=CertificateType.TLS_SERVER,
                                                                              caa_domains=['ca111.com']))
        caa_checker = TestMpicCaaChecker.create_configured_caa_checker()
        caa_response = await caa_checker.check_caa(caa_request)
        expected_records_seen = [record_data.to_text() for record_data in test_dns_query_answer.rrset]
        check_response_details = CaaCheckResponseDetails(caa_record_present=True, found_at='example.com', records_seen=expected_records_seen)
        assert self.is_result_as_expected(caa_response, True, check_response_details) is True

    async def check_caa__should_allow_issuance_given_matching_caa_record_found_in_parent_of_nonexistent_domain(self, set_env_variables, mocker):
        record_name, expected_domain = 'example.com', 'example.com.'
        test_dns_query_answer = MockDnsObjectCreator.create_caa_query_answer(record_name, 0, 'issue', 'ca111.com', mocker)
        self.patch_resolver_with_conditional_answer_and_exception(mocker, expected_domain, test_dns_query_answer, dns.resolver.NXDOMAIN)
        caa_request = CaaCheckRequest(domain_or_ip_target='nonexistent.example.com', caa_check_parameters=CaaCheckParameters(
            certificate_type=CertificateType.TLS_SERVER, caa_domains=['ca111.com']))
        caa_checker = TestMpicCaaChecker.create_configured_caa_checker()
        caa_response = await caa_checker.check_caa(caa_request)
        assert caa_response.check_passed is True

    async def check_caa__should_disallow_issuance_given_non_matching_caa_record_found(self, set_env_variables, mocker):
        record_name, expected_domain = 'example.com', 'example.com.'
        test_dns_query_answer = MockDnsObjectCreator.create_caa_query_answer(record_name, 0, 'issue', 'ca222.com', mocker)
        self.patch_resolver_with_conditional_answer_and_exception(mocker, expected_domain, test_dns_query_answer, dns.resolver.NoAnswer)
        caa_request = CaaCheckRequest(domain_or_ip_target='example.com', caa_check_parameters=CaaCheckParameters(
            certificate_type=CertificateType.TLS_SERVER, caa_domains=['ca111.com']))
        caa_checker = TestMpicCaaChecker.create_configured_caa_checker()
        caa_response = await caa_checker.check_caa(caa_request)
        assert caa_response.check_passed is False

    async def check_caa__should_allow_issuance_relying_on_default_caa_domains(self, set_env_variables, mocker):
        record_name, expected_domain = 'example.com', 'example.com.'
        test_dns_query_answer = MockDnsObjectCreator.create_caa_query_answer(record_name, 0, 'issue', 'ca2.net', mocker)
        self.patch_resolver_with_conditional_answer_and_exception(mocker, expected_domain, test_dns_query_answer, dns.resolver.NoAnswer)
        caa_request = CaaCheckRequest(domain_or_ip_target='example.com')
        caa_checker = TestMpicCaaChecker.create_configured_caa_checker()
        caa_response = await caa_checker.check_caa(caa_request)
        assert caa_response.check_passed is True

    async def check_caa__should_include_timestamp_in_nanos_in_result(self, set_env_variables, mocker):
        self.patch_resolver_with_answer_or_exception(mocker, dns.resolver.NoAnswer())
        caa_request = CaaCheckRequest(domain_or_ip_target='example.com', caa_check_parameters=CaaCheckParameters(
                                          certificate_type=CertificateType.TLS_SERVER, caa_domains=['ca111.com']))
        caa_checker = TestMpicCaaChecker.create_configured_caa_checker()
        caa_response = await caa_checker.check_caa(caa_request)
        assert caa_response.timestamp_ns is not None

    async def check_caa__should_return_failure_response_with_errors_given_error_in_dns_lookup(self, set_env_variables, mocker):
        self.patch_resolver_with_answer_or_exception(mocker, dns.resolver.NoNameservers)
        caa_request = CaaCheckRequest(domain_or_ip_target='example.com', caa_check_parameters=CaaCheckParameters(
                                          certificate_type=CertificateType.TLS_SERVER, caa_domains=['ca111.com']))
        caa_checker = TestMpicCaaChecker.create_configured_caa_checker()
        caa_response = await caa_checker.check_caa(caa_request)
        check_response_details = CaaCheckResponseDetails(caa_record_present=None)  # if error, don't know this detail
        errors = [MpicValidationError(error_type=ErrorMessages.CAA_LOOKUP_ERROR.key, error_message=ErrorMessages.CAA_LOOKUP_ERROR.message)]
        assert self.is_result_as_expected(caa_response, False, check_response_details, errors) is True

    @pytest.mark.parametrize('caa_answer_value, check_passed', [('ca1allowed.org', True), ('ca1notallowed.org', False)])
    async def check_caa__should_return_rrset_and_domain_given_domain_with_caa_record_on_success_or_failure(self, set_env_variables, caa_answer_value, check_passed, mocker):
        record_name, expected_domain = 'example.com', 'example.com.'
        test_dns_query_answer = MockDnsObjectCreator.create_caa_query_answer(record_name, 0, 'issue', caa_answer_value, mocker)
        self.patch_resolver_with_conditional_answer_and_exception(mocker, expected_domain, test_dns_query_answer, dns.resolver.NoAnswer)
        caa_request = CaaCheckRequest(domain_or_ip_target='example.com', caa_check_parameters=CaaCheckParameters(
            certificate_type=CertificateType.TLS_SERVER, caa_domains=['ca1allowed.org']))
        caa_checker = TestMpicCaaChecker.create_configured_caa_checker()
        caa_response = await caa_checker.check_caa(caa_request)
        assert caa_response.check_passed == check_passed
        assert caa_response.details.found_at == 'example.com'
        assert caa_response.details.records_seen == [f"0 issue \"{caa_answer_value}\""]

    async def check_caa__should_return_rrset_and_domain_given_extra_subdomain(self, set_env_variables, mocker):
        record_name, expected_domain = 'example.com', 'example.com.'
        test_dns_query_answer = MockDnsObjectCreator.create_caa_query_answer(record_name, 0, 'issue', 'ca1.org', mocker)
        self.patch_resolver_with_conditional_answer_and_exception(mocker, expected_domain, test_dns_query_answer, dns.resolver.NoAnswer)
        caa_request = CaaCheckRequest(domain_or_ip_target='example.com', caa_check_parameters=CaaCheckParameters(
            certificate_type=CertificateType.TLS_SERVER, caa_domains=None))
        caa_checker = TestMpicCaaChecker.create_configured_caa_checker()
        caa_response = await caa_checker.check_caa(caa_request)
        assert caa_response.details.found_at == 'example.com'
        assert caa_response.details.records_seen == ['0 issue "ca1.org"']

    async def check_caa__should_return_no_rrset_and_no_domain_given_no_caa_record_for_domain(self, set_env_variables, mocker):
        record_name, expected_domain = 'example.com', 'example.org.'  # DIFFERENT domain expected in  mock
        test_dns_query_answer = MockDnsObjectCreator.create_caa_query_answer(record_name, 0, 'issue', 'ca1.org', mocker)
        self.patch_resolver_with_conditional_answer_and_exception(mocker, expected_domain, test_dns_query_answer, dns.resolver.NoAnswer)
        caa_request = CaaCheckRequest(domain_or_ip_target='example.com', caa_check_parameters=CaaCheckParameters(
            certificate_type=CertificateType.TLS_SERVER, caa_domains=None))
        caa_checker = TestMpicCaaChecker.create_configured_caa_checker()
        caa_response = await caa_checker.check_caa(caa_request)
        assert caa_response.details.found_at is None
        assert caa_response.details.records_seen is None

    @pytest.mark.parametrize('target_domain, record_present', [('example.com', True), ('example.org', False)])
    async def check_caa__should_return_whether_caa_record_was_found(self, set_env_variables, target_domain, record_present, mocker):
        record_name, expected_domain = 'example.com', 'example.com.'
        test_dns_query_answer = MockDnsObjectCreator.create_caa_query_answer(record_name, 0, 'issue', 'ca1.org', mocker)
        self.patch_resolver_with_conditional_answer_and_exception(mocker, expected_domain, test_dns_query_answer, dns.resolver.NoAnswer)
        mocker.patch('dns.resolver.resolve', side_effect=lambda domain_name, rdtype: (
            test_dns_query_answer if domain_name.to_text() == 'example.com.' else self.raise_(dns.resolver.NoAnswer)
        ))
        caa_request = CaaCheckRequest(domain_or_ip_target=target_domain, caa_check_parameters=CaaCheckParameters(
            certificate_type=CertificateType.TLS_SERVER, caa_domains=None))
        caa_checker = TestMpicCaaChecker.create_configured_caa_checker()
        caa_response = await caa_checker.check_caa(caa_request)
        assert caa_response.details.caa_record_present == record_present

    async def check_caa__should_support_wildcard_domain(self, set_env_variables, mocker):
        record_name, expected_domain = '*.example.com', '*.example.com.'
        test_dns_query_answer = MockDnsObjectCreator.create_caa_query_answer(record_name, 0, 'issue', 'ca1.com', mocker)
        self.patch_resolver_with_conditional_answer_and_exception(mocker, expected_domain, test_dns_query_answer, dns.resolver.NoAnswer)
        caa_request = CaaCheckRequest(domain_or_ip_target='*.example.com', caa_check_parameters=CaaCheckParameters(
            certificate_type=CertificateType.TLS_SERVER_WILDCARD, caa_domains=None))
        caa_checker = TestMpicCaaChecker.create_configured_caa_checker()
        caa_response = await caa_checker.check_caa(caa_request)
        assert caa_response.check_passed is True

    @pytest.mark.parametrize('property_tag, property_value', [('contactemail', 'contactme@example.com'), ('contactphone', '+1 (555) 555-5555')])
    async def check_caa__should_accommodate_contact_info_properties_in_caa_records(self, set_env_variables, property_tag, property_value, mocker):
        records = [MockDnsObjectCreator.create_caa_record(0, 'issue', 'ca1.com'),
                   MockDnsObjectCreator.create_caa_record(0, property_tag, property_value)]
        test_dns_query_answer = MockDnsObjectCreator.create_dns_query_answer_with_multiple_records(
            'example.com', '', DnsRecordType.CAA, *records, mocker=mocker)
        self.patch_resolver_with_answer_or_exception(mocker, test_dns_query_answer)
        mocker.patch('dns.resolver.resolve', side_effect=lambda domain_name, rdtype: test_dns_query_answer)
        caa_request = CaaCheckRequest(domain_or_ip_target='example.com', caa_check_parameters=CaaCheckParameters(
            certificate_type=CertificateType.TLS_SERVER, caa_domains=None))
        caa_checker = TestMpicCaaChecker.create_configured_caa_checker()
        caa_response = await caa_checker.check_caa(caa_request)
        assert caa_response.check_passed is True
        assert caa_response.details.records_seen == [f'0 issue "ca1.com"', f'0 {property_tag} "{property_value}"']

    @pytest.mark.parametrize('value_list, caa_domains', [
        (['ca111.org'], ['ca111.org']),
        (['ca111.org', 'ca222.com'], ['ca222.com']),
        (['ca111.org', 'ca222.com'], ['ca333.net', 'ca111.org']),
    ])
    def does_value_list_permit_issuance__should_return_true_given_one_value_found_in_caa_domains(self, value_list, caa_domains):
        result = MpicCaaChecker.does_value_list_permit_issuance(value_list, caa_domains)
        assert result is True

    def does_value_list_permit_issuance__should_return_false_given_value_not_found_in_caa_domains(self):
        value_list = ['ca222.org']
        caa_domains = ['ca111.com']
        result = MpicCaaChecker.does_value_list_permit_issuance(value_list, caa_domains)
        assert result is False

    def does_value_list_permit_issuance__should_return_false_given_only_values_with_extensions(self):
        value_list = ['0 issue "ca111.com; policy=ev"']
        caa_domains = ['ca111.com']
        result = MpicCaaChecker.does_value_list_permit_issuance(value_list, caa_domains)
        assert result is False

    def does_value_list_permit_issuance__should_ignore_whitespace_around_values(self):
        value_list = ['  ca111.com  ']
        caa_domains = ['ca111.com']
        result = MpicCaaChecker.does_value_list_permit_issuance(value_list, caa_domains)
        assert result is True

    def is_valid_for_issuance__should_return_true_given_issue_tag_for_non_wildcard_domain(self):
        records = [MockDnsObjectCreator.create_caa_record(0, 'issue', 'ca1.org')]
        test_rrset = MockDnsObjectCreator.create_rrset(dns.rdatatype.CAA, *records)
        result = MpicCaaChecker.is_valid_for_issuance(caa_domains=['ca1.org'], is_wc_domain=False, rrset=test_rrset)
        assert result is True

    def is_valid_for_issuance__should_return_true_given_issue_tag_for_wildcard_domain(self):
        records = [MockDnsObjectCreator.create_caa_record(0, 'issue', 'ca1.org')]
        test_rrset = MockDnsObjectCreator.create_rrset(dns.rdatatype.CAA, *records)
        result = MpicCaaChecker.is_valid_for_issuance(caa_domains=['ca1.org'], is_wc_domain=True, rrset=test_rrset)
        assert result is True

    def is_valid_for_issuance__should_return_true_given_issuewild_tag_for_wildcard_domain(self):
        records = [MockDnsObjectCreator.create_caa_record(0, 'issuewild', 'ca1.org'),
                   MockDnsObjectCreator.create_caa_record(0, 'issue', 'ca2.org')]
        test_rrset = MockDnsObjectCreator.create_rrset(dns.rdatatype.CAA, *records)
        result = MpicCaaChecker.is_valid_for_issuance(caa_domains=['ca1.org'], is_wc_domain=True, rrset=test_rrset)
        assert result is True

    def is_valid_for_issuance__should_return_true_given_no_issue_tags_and_issuewild_tag_for_wildcard_domain(self):
        records = [MockDnsObjectCreator.create_caa_record(0, 'issuewild', 'ca1.org')]
        test_rrset = MockDnsObjectCreator.create_rrset(dns.rdatatype.CAA, *records)
        result = MpicCaaChecker.is_valid_for_issuance(caa_domains=['ca1.org'], is_wc_domain=True, rrset=test_rrset)
        assert result is True

    def is_valid_for_issuance__should_return_true_given_issuewild_disallowed_for_all_and_issue_tag_found(self):
        records = [MockDnsObjectCreator.create_caa_record(0, 'issue', 'ca1.org'),
                   MockDnsObjectCreator.create_caa_record(0, 'issuewild', ';')]
        test_rrset = MockDnsObjectCreator.create_rrset(dns.rdatatype.CAA, *records)
        result = MpicCaaChecker.is_valid_for_issuance(caa_domains=['ca1.org'], is_wc_domain=False, rrset=test_rrset)
        assert result is True

    def is_valid_for_issuance__should_return_true_given_no_issue_tags_found(self):
        records = [MockDnsObjectCreator.create_caa_record(0, 'unknown', 'ca1.org')]
        test_rrset = MockDnsObjectCreator.create_rrset(dns.rdatatype.CAA, *records)
        result = MpicCaaChecker.is_valid_for_issuance(caa_domains=['ca1.org'], is_wc_domain=False, rrset=test_rrset)
        assert result is True

    def is_valid_for_issuance__should_return_false_given_issue_tags_for_other_certificate_authorities_only(self):
        records = [MockDnsObjectCreator.create_caa_record(0, 'issue', 'ca5.org')]
        test_rrset = MockDnsObjectCreator.create_rrset(dns.rdatatype.CAA, *records)
        result = MpicCaaChecker.is_valid_for_issuance(caa_domains=['ca1.org'], is_wc_domain=False, rrset=test_rrset)
        assert result is False

    @pytest.mark.parametrize('known_tag', ['issue', 'issuewild'])  # TODO what about issuewild, issuemail, and iodef? (they fail)
    def is_valid_for_issuance__should_return_true_given_critical_flag_and_known_tag(self, known_tag):
        records = [MockDnsObjectCreator.create_caa_record(128, known_tag, 'ca1.org')]
        test_rrset = MockDnsObjectCreator.create_rrset(dns.rdatatype.CAA, *records)
        result = MpicCaaChecker.is_valid_for_issuance(caa_domains=['ca1.org'], is_wc_domain=False, rrset=test_rrset)
        assert result is True

    def is_valid_for_issuance__should_return_false_given_critical_flag_for_an_unknown_tag(self):
        records = [MockDnsObjectCreator.create_caa_record(128, 'mystery', 'ca1.org'),
                   MockDnsObjectCreator.create_caa_record(0, 'issue', 'ca1.org')]
        test_rrset = MockDnsObjectCreator.create_rrset(dns.rdatatype.CAA, *records)
        result = MpicCaaChecker.is_valid_for_issuance(caa_domains=['ca1.org'], is_wc_domain=False, rrset=test_rrset)
        assert result is False

    def is_valid_for_issuance__should_return_false_given_issuewild_disallowed_for_all_and_wildcard_domain(self):
        records = [MockDnsObjectCreator.create_caa_record(0, 'issue', 'ca1.org'),
                   MockDnsObjectCreator.create_caa_record(0, 'issuewild', ';')]
        test_rrset = MockDnsObjectCreator.create_rrset(dns.rdatatype.CAA, *records)
        result = MpicCaaChecker.is_valid_for_issuance(caa_domains=['ca1.org'], is_wc_domain=True, rrset=test_rrset)
        assert result is False

    @pytest.mark.parametrize('issue_tag', ['ISSUE', 'IsSuE'])
    def is_valid_for_issuance__should_return_true_given_nonstandard_casing_in_issue_tag(self, issue_tag):
        records = [MockDnsObjectCreator.create_caa_record(0, issue_tag, 'ca1.org')]
        test_rrset = MockDnsObjectCreator.create_rrset(dns.rdatatype.CAA, *records)
        result = MpicCaaChecker.is_valid_for_issuance(caa_domains=['ca1.org'], is_wc_domain=False, rrset=test_rrset)
        assert result is True

    def is_valid_for_issuance__should_return_false_given_attempted_xss_via_caa_record(self):
        records = [MockDnsObjectCreator.create_caa_record(0, 'issue', 'ca1.org <script>alert("XSS")</script>')]
        test_rrset = MockDnsObjectCreator.create_rrset(dns.rdatatype.CAA, *records)
        result = MpicCaaChecker.is_valid_for_issuance(caa_domains=['ca1.org'], is_wc_domain=False, rrset=test_rrset)
        assert result is False

    @pytest.mark.skip(reason='Checks for DNSSEC validity are not yet implemented')
    def is_valid_for_issuance__should_return_false_given_expired_dnssec_signature(self):
        records = [MockDnsObjectCreator.create_caa_record(0, 'issue', 'ca1.org')]
        test_rrset = MockDnsObjectCreator.create_rrset(dns.rdatatype.CAA, *records)
        result = MpicCaaChecker.is_valid_for_issuance(caa_domains=['ca1.org'], is_wc_domain=False, rrset=test_rrset)
        assert result is False

    @pytest.mark.parametrize('domain_1_tag, domain_1_value, expected_result', [
        ('issue', ';', False), ('issue', 'ca2.org', False), ('mystery', 'ca2.org', True)
    ])
    def is_valid_for_issuance__should_ignore_issuewild_tags_given_non_wildcard_domain(self, domain_1_tag, domain_1_value, expected_result):
        records = [MockDnsObjectCreator.create_caa_record(0, domain_1_tag, domain_1_value),
                   MockDnsObjectCreator.create_caa_record(0, 'issuewild', 'ca1.org')]
        test_rrset = MockDnsObjectCreator.create_rrset(dns.rdatatype.CAA, *records)
        result = MpicCaaChecker.is_valid_for_issuance(caa_domains=['ca1.org'], is_wc_domain=False, rrset=test_rrset)
        assert result is expected_result

    def raise_(self, ex):
        # noinspection PyUnusedLocal
        def _raise(*args, **kwargs):
            raise ex
        return _raise()

    def is_result_as_expected(self, result, check_passed, check_response_details, errors=None):
        result.timestamp_ns = None  # ignore timestamp for comparison
        expected_result = CaaCheckResponse(perspective_code='us-east-4', check_passed=check_passed, details=check_response_details, errors=errors)
        return result == expected_result  # Pydantic allows direct comparison with equality operator

    def patch_resolver_resolve_with_side_effect(self, mocker, side_effect):
        return mocker.patch('dns.asyncresolver.resolve', new_callable=AsyncMock, side_effect=side_effect)

    def patch_resolver_with_answer_or_exception(self, mocker, mocked_answer_or_exception):
        # noinspection PyUnusedLocal
        async def side_effect(domain_name, rdtype):
            if isinstance(mocked_answer_or_exception, Exception):
                raise mocked_answer_or_exception
            return mocked_answer_or_exception

        return self.patch_resolver_resolve_with_side_effect(mocker, side_effect)

    def patch_resolver_with_conditional_answer_and_exception(self, mocker, expected_domain, mocked_answer, exception):
        # noinspection PyUnusedLocal
        async def side_effect(domain_name, rdtype):
            if domain_name.to_text() == expected_domain:
                return mocked_answer
            else:
                raise exception

        self.patch_resolver_resolve_with_side_effect(mocker, side_effect)


if __name__ == '__main__':
    pytest.main()
