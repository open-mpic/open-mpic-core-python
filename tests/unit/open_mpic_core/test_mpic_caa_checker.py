import logging
from io import StringIO

import dns
import pytest

from unittest.mock import AsyncMock

from open_mpic_core import CaaCheckParameters
from open_mpic_core import CaaCheckRequest, CaaCheckResponse, CaaCheckResponseDetails
from open_mpic_core import CertificateType
from open_mpic_core import DnsRecordType
from open_mpic_core import ErrorMessages
from open_mpic_core import MpicCaaChecker
from open_mpic_core import TRACE_LEVEL

from unit.test_util.mock_dns_object_creator import MockDnsObjectCreator


# noinspection PyMethodMayBeStatic
class TestMpicCaaChecker:
    @staticmethod
    @pytest.fixture(scope="class", autouse=True)
    def set_env_variables():
        envvars = {
            "default_caa_domains": "ca1.com|ca2.net|ca3.org",
        }
        with pytest.MonkeyPatch.context() as class_scoped_monkeypatch:
            for k, v in envvars.items():
                class_scoped_monkeypatch.setenv(k, v)
            yield class_scoped_monkeypatch  # restore the environment afterward

    @pytest.fixture(autouse=True)
    def setup_logging(self):
        # Clear existing handlers
        root = logging.getLogger()
        for handler in root.handlers[:]:
            root.removeHandler(handler)

        # noinspection PyAttributeOutsideInit
        self.log_output = StringIO()  # to be able to inspect what gets logged
        handler = logging.StreamHandler(self.log_output)
        handler.setFormatter(logging.Formatter("%(asctime)s - %(name)s - %(levelname)s - %(message)s"))

        # Configure fresh logging
        logging.basicConfig(level=TRACE_LEVEL, handlers=[handler])
        yield

    @staticmethod
    def create_configured_caa_checker(log_level=None):
        return MpicCaaChecker(["ca1.com", "ca2.net", "ca3.org"], log_level)

    def constructor__should_set_log_level_if_provided(self):
        caa_checker = TestMpicCaaChecker.create_configured_caa_checker(logging.ERROR)
        assert caa_checker.logger.level == logging.ERROR

    def mpic_caa_checker__should_be_able_to_log_at_trace_level(self):
        caa_checker = TestMpicCaaChecker.create_configured_caa_checker(TRACE_LEVEL)
        test_message = "This is a trace log message."
        caa_checker.logger.trace(test_message)
        log_contents = self.log_output.getvalue()
        assert all(text in log_contents for text in [test_message, "TRACE", caa_checker.logger.name])

    # integration test of a sort -- only mocking dns methods rather than remaining class methods
    async def check_caa__should_allow_issuance_given_no_caa_records_found(self, mocker):
        self.patch_resolver_with_answer_or_exception(mocker, dns.resolver.NoAnswer())
        caa_request = CaaCheckRequest(
            domain_or_ip_target="example.com",
            caa_check_parameters=CaaCheckParameters(
                certificate_type=CertificateType.TLS_SERVER, caa_domains=["ca111.com"]
            ),
        )
        caa_checker = TestMpicCaaChecker.create_configured_caa_checker()
        caa_response = await caa_checker.check_caa(caa_request)
        check_response_details = CaaCheckResponseDetails(caa_record_present=False)
        caa_response.timestamp_ns = None  # ignore timestamp for comparison
        expected_response = CaaCheckResponse(
            check_passed=True,
            check_completed=True,
            details=check_response_details,
        )
        assert caa_response == expected_response

    async def check_caa__should_allow_issuance_given_matching_caa_record_found(self, mocker):
        record_name, expected_domain = "example.com", "example.com."
        test_dns_query_answer = MockDnsObjectCreator.create_caa_query_answer(
            record_name, 0, "issue", "ca111.com", mocker
        )
        self.patch_resolver_to_expect_domain(mocker, expected_domain, test_dns_query_answer, dns.resolver.NoAnswer)

        caa_request = self.create_caa_check_request("example.com", ["ca111.com"])
        caa_checker = TestMpicCaaChecker.create_configured_caa_checker()
        caa_response = await caa_checker.check_caa(caa_request)
        expected_records_seen = [record_data.to_text() for record_data in test_dns_query_answer.rrset]
        check_response_details = CaaCheckResponseDetails(
            caa_record_present=True, found_at="example.com", records_seen=expected_records_seen
        )
        caa_response.timestamp_ns = None  # ignore timestamp for comparison
        expected_response = CaaCheckResponse(
            check_passed=True,
            check_completed=True,
            details=check_response_details,
        )
        assert caa_response == expected_response

    async def check_caa__should_allow_smime_issuance_given_matching_caa_issuemail_record_found(self, mocker):
        record_name, expected_domain = "example.com", "example.com."
        test_dns_query_answer = MockDnsObjectCreator.create_caa_query_answer(
            record_name, 0, "issuemail", "ca111.com", mocker
        )
        self.patch_resolver_to_expect_domain(mocker, expected_domain, test_dns_query_answer, dns.resolver.NoAnswer)

        caa_request = self.create_caa_check_request("example.com", ["ca111.com"])
        caa_request.caa_check_parameters.certificate_type = CertificateType.S_MIME
        caa_checker = TestMpicCaaChecker.create_configured_caa_checker()
        caa_response = await caa_checker.check_caa(caa_request)
        expected_records_seen = [record_data.to_text() for record_data in test_dns_query_answer.rrset]
        check_response_details = CaaCheckResponseDetails(
            caa_record_present=True, found_at="example.com", records_seen=expected_records_seen
        )
        caa_response.timestamp_ns = None  # ignore timestamp for comparison
        expected_response = CaaCheckResponse(
            check_passed=True,
            check_completed=True,
            details=check_response_details,
        )
        assert caa_response == expected_response

    @pytest.mark.parametrize(
        "domain, encoded_domain", [("bücher.example.de", "xn--bcher-kva.example.de."), ("café.com", "xn--caf-dma.com.")]
    )
    async def check_caa__should_handle_domains_with_non_ascii_characters(self, domain, encoded_domain, mocker):
        test_dns_query_answer = MockDnsObjectCreator.create_caa_query_answer(
            encoded_domain, 0, "issue", "ca111.com", mocker
        )
        self.patch_resolver_to_expect_domain(mocker, encoded_domain, test_dns_query_answer, dns.resolver.NoAnswer)
        caa_request = self.create_caa_check_request(domain, ["ca111.com"])
        caa_checker = TestMpicCaaChecker.create_configured_caa_checker()
        caa_response = await caa_checker.check_caa(caa_request)
        assert caa_response.details.records_seen == [
            record_data.to_text() for record_data in test_dns_query_answer.rrset
        ]
        assert caa_response.check_passed is True

    async def check_caa__should_allow_issuance_given_matching_caa_record_found_in_parent_of_nonexistent_domain(
        self, mocker
    ):
        record_name, expected_domain = "example.com", "example.com."
        test_dns_query_answer = MockDnsObjectCreator.create_caa_query_answer(
            record_name, 0, "issue", "ca111.com", mocker
        )
        self.patch_resolver_to_expect_domain(mocker, expected_domain, test_dns_query_answer, dns.resolver.NXDOMAIN)
        caa_request = self.create_caa_check_request("nonexistent.example.com", ["ca111.com"])
        caa_checker = TestMpicCaaChecker.create_configured_caa_checker()
        caa_response = await caa_checker.check_caa(caa_request)
        assert caa_response.check_passed is True

    async def check_caa__should_disallow_issuance_given_non_matching_caa_record_found(self, mocker):
        record_name, expected_domain = "example.com", "example.com."
        test_dns_query_answer = MockDnsObjectCreator.create_caa_query_answer(
            record_name, 0, "issue", "ca222.com", mocker
        )
        self.patch_resolver_to_expect_domain(mocker, expected_domain, test_dns_query_answer, dns.resolver.NoAnswer)
        caa_request = self.create_caa_check_request("example.com", ["ca111.com"])
        caa_checker = TestMpicCaaChecker.create_configured_caa_checker()
        caa_response = await caa_checker.check_caa(caa_request)
        assert caa_response.check_passed is False

    async def check_caa__should_disallow_smime_issuance_given_non_matching_caa_issuemail_record_found(self, mocker):
        record_name, expected_domain = "example.com", "example.com."
        test_dns_query_answer = MockDnsObjectCreator.create_caa_query_answer(
            record_name, 0, "issuemail", "ca222.com", mocker
        )
        self.patch_resolver_to_expect_domain(mocker, expected_domain, test_dns_query_answer, dns.resolver.NoAnswer)
        caa_request = self.create_caa_check_request("example.com", ["ca111.com"])
        caa_request.caa_check_parameters.certificate_type = CertificateType.S_MIME
        caa_checker = TestMpicCaaChecker.create_configured_caa_checker()
        caa_response = await caa_checker.check_caa(caa_request)
        assert caa_response.check_passed is False

    async def check_caa__should_allow_issuance_relying_on_default_caa_domains(self, mocker):
        record_name, expected_domain = "example.com", "example.com."
        test_dns_query_answer = MockDnsObjectCreator.create_caa_query_answer(record_name, 0, "issue", "ca2.net", mocker)
        self.patch_resolver_to_expect_domain(mocker, expected_domain, test_dns_query_answer, dns.resolver.NoAnswer)
        caa_request = CaaCheckRequest(domain_or_ip_target="example.com")
        caa_checker = TestMpicCaaChecker.create_configured_caa_checker()
        caa_response = await caa_checker.check_caa(caa_request)
        assert caa_response.check_passed is True

    @pytest.mark.parametrize("should_complete_check", [True, False])
    async def check_caa__should_set_check_completed_true_if_no_errors_encountered_and_false_otherwise(
        self, should_complete_check, mocker
    ):
        caa_checker = TestMpicCaaChecker.create_configured_caa_checker()
        if should_complete_check:
            self.patch_resolver_with_answer_or_exception(mocker, dns.resolver.NoAnswer())
        else:
            self.patch_resolver_with_answer_or_exception(mocker, dns.exception.Timeout())
        caa_request = self.create_caa_check_request("example.com", ["ca111.com"])
        caa_request.trace_identifier = "test_trace_identifier"
        caa_result = await caa_checker.check_caa(caa_request)
        assert caa_result.check_passed is should_complete_check
        assert caa_result.check_completed is should_complete_check

    async def check_caa__should_include_timestamp_in_nanos_in_result(self, mocker):
        self.patch_resolver_with_answer_or_exception(mocker, dns.resolver.NoAnswer())
        caa_request = self.create_caa_check_request("example.com", ["ca111.com"])
        caa_checker = TestMpicCaaChecker.create_configured_caa_checker()
        caa_response = await caa_checker.check_caa(caa_request)
        assert caa_response.timestamp_ns is not None

    async def check_caa__should_return_failure_response_with_errors_given_error_in_dns_lookup(self, mocker):
        dns_lookup_error = dns.resolver.NoNameservers(
            request=dns.message.make_query("example.com", "CAA", "IN"),
            errors=[
                ("192.0.2.1", True, 53, dns.exception.Timeout("Timeout resolving example.com"))
            ],  # List of (server, error) tuples
        )
        self.patch_resolver_with_answer_or_exception(mocker, dns_lookup_error)
        caa_request = self.create_caa_check_request("example.com", ["ca111.com"])
        caa_checker = TestMpicCaaChecker.create_configured_caa_checker()
        caa_response = await caa_checker.check_caa(caa_request)
        check_response_details = CaaCheckResponseDetails(caa_record_present=None)  # if error, don't know this detail
        caa_response.timestamp_ns = None  # ignore timestamp for comparison
        assert caa_response.check_passed is False
        assert caa_response.check_completed is False
        assert caa_response.details == check_response_details
        assert caa_response.errors[0].error_type == ErrorMessages.CAA_LOOKUP_ERROR.key
        assert "Timeout resolving example.com" in caa_response.errors[0].error_message

    @pytest.mark.parametrize("caa_answer_value, check_passed", [("ca1allowed.org", True), ("ca1notallowed.org", False)])
    async def check_caa__should_return_rrset_and_domain_given_domain_with_caa_record_on_success_or_failure(
        self, caa_answer_value, check_passed, mocker
    ):
        record_name, expected_domain = "example.com", "example.com."
        test_dns_query_answer = MockDnsObjectCreator.create_caa_query_answer(
            record_name, 0, "issue", caa_answer_value, mocker
        )
        self.patch_resolver_to_expect_domain(mocker, expected_domain, test_dns_query_answer, dns.resolver.NoAnswer)
        caa_request = self.create_caa_check_request("example.com", ["ca1allowed.org"])
        caa_checker = TestMpicCaaChecker.create_configured_caa_checker()
        caa_response = await caa_checker.check_caa(caa_request)
        assert caa_response.check_passed == check_passed
        assert caa_response.details.found_at == "example.com"
        assert caa_response.details.records_seen == [f'0 issue "{caa_answer_value}"']

    async def check_caa__should_return_rrset_and_domain_given_extra_subdomain(self, mocker):
        record_name, expected_domain = "example.com", "example.com."
        test_dns_query_answer = MockDnsObjectCreator.create_caa_query_answer(record_name, 0, "issue", "ca1.org", mocker)
        self.patch_resolver_to_expect_domain(mocker, expected_domain, test_dns_query_answer, dns.resolver.NoAnswer)
        caa_request = self.create_caa_check_request("example.com", None)
        caa_checker = TestMpicCaaChecker.create_configured_caa_checker()
        caa_response = await caa_checker.check_caa(caa_request)
        assert caa_response.details.found_at == "example.com"
        assert caa_response.details.records_seen == ['0 issue "ca1.org"']

    async def check_caa__should_return_no_rrset_and_no_domain_given_no_caa_record_for_domain(self, mocker):
        record_name, expected_domain = "example.com", "example.org."  # DIFFERENT domain expected in  mock
        test_dns_query_answer = MockDnsObjectCreator.create_caa_query_answer(record_name, 0, "issue", "ca1.org", mocker)
        self.patch_resolver_to_expect_domain(mocker, expected_domain, test_dns_query_answer, dns.resolver.NoAnswer)
        caa_request = self.create_caa_check_request("example.com", None)
        caa_checker = TestMpicCaaChecker.create_configured_caa_checker()
        caa_response = await caa_checker.check_caa(caa_request)
        assert caa_response.details.found_at is None
        assert caa_response.details.records_seen is None

    @pytest.mark.parametrize("target_domain, record_present", [("example.com", True), ("example.org", False)])
    async def check_caa__should_return_whether_caa_record_was_found(self, target_domain, record_present, mocker):
        record_name, expected_domain = "example.com", "example.com."
        test_dns_query_answer = MockDnsObjectCreator.create_caa_query_answer(record_name, 0, "issue", "ca1.org", mocker)
        self.patch_resolver_to_expect_domain(mocker, expected_domain, test_dns_query_answer, dns.resolver.NoAnswer)
        mocker.patch(
            "dns.resolver.resolve",
            side_effect=lambda domain_name, rdtype: (
                test_dns_query_answer if domain_name.to_text() == "example.com." else self.raise_(dns.resolver.NoAnswer)
            ),
        )
        caa_request = self.create_caa_check_request(target_domain, None)
        caa_checker = TestMpicCaaChecker.create_configured_caa_checker()
        caa_response = await caa_checker.check_caa(caa_request)
        assert caa_response.details.caa_record_present == record_present

    async def check_caa__should_support_wildcard_domain(self, mocker):
        record_name, expected_domain = "foo.example.com", "foo.example.com."
        test_dns_query_answer = MockDnsObjectCreator.create_caa_query_answer(record_name, 0, "issue", "ca1.com", mocker)
        # throwing base Exception to ensure correct domain in DNS lookup (asterisk is removed prior); previously a bug
        self.patch_resolver_to_expect_domain(mocker, expected_domain, test_dns_query_answer, Exception)
        caa_request = CaaCheckRequest(
            domain_or_ip_target="*.foo.example.com",
            caa_check_parameters=CaaCheckParameters(certificate_type=CertificateType.TLS_SERVER, caa_domains=None),
        )
        caa_checker = TestMpicCaaChecker.create_configured_caa_checker()
        caa_response = await caa_checker.check_caa(caa_request)
        assert caa_response.check_passed is True

    @pytest.mark.parametrize(
        "property_tag, property_value",
        [("contactemail", "contactme@example.com"), ("contactphone", "+1 (555) 555-5555")],
    )
    async def check_caa__should_accommodate_contact_info_properties_in_caa_records(
        self, property_tag, property_value, mocker
    ):
        records = [
            MockDnsObjectCreator.create_caa_record(0, "issue", "ca1.com"),
            MockDnsObjectCreator.create_caa_record(0, property_tag, property_value),
        ]
        test_dns_query_answer = MockDnsObjectCreator.create_dns_query_answer_with_multiple_records(
            "example.com", "", DnsRecordType.CAA, *records, mocker=mocker
        )
        self.patch_resolver_with_answer_or_exception(mocker, test_dns_query_answer)
        mocker.patch("dns.resolver.resolve", side_effect=lambda domain_name, rdtype: test_dns_query_answer)
        caa_request = self.create_caa_check_request("example.com", None)
        caa_checker = TestMpicCaaChecker.create_configured_caa_checker()
        caa_response = await caa_checker.check_caa(caa_request)
        assert caa_response.check_passed is True
        assert caa_response.details.records_seen == [f'0 issue "ca1.com"', f'0 {property_tag} "{property_value}"']

    async def check_caa__should_be_able_to_trace_timing_of_caa_lookup(self, mocker):
        caa_checker = TestMpicCaaChecker.create_configured_caa_checker(TRACE_LEVEL)  # note the TRACE_LEVEL here
        self.patch_resolver_with_answer_or_exception(mocker, dns.resolver.NoAnswer())
        caa_request = self.create_caa_check_request("example.com", ["ca111.com"])
        await caa_checker.check_caa(caa_request)
        # Get the log output and assert
        log_contents = self.log_output.getvalue()
        assert all(text in log_contents for text in ["seconds", "TRACE", caa_checker.logger.name])

    async def check_caa__should_include_trace_identifier_in_logs_if_included_in_request(self, mocker):
        caa_checker = TestMpicCaaChecker.create_configured_caa_checker()
        self.patch_resolver_with_answer_or_exception(mocker, dns.exception.Timeout())
        caa_request = self.create_caa_check_request("example.com", ["ca111.com"])
        caa_request.trace_identifier = "test_trace_identifier"
        caa_result = await caa_checker.check_caa(caa_request)
        log_contents = self.log_output.getvalue()
        assert caa_result.check_passed is False
        assert "test_trace_identifier" in log_contents

    # fmt: off
    # noinspection PyUnusedLocal
    @pytest.mark.parametrize("test_description, caa_value, expected_domain, expected_parameters", [
        ("empty value (just whitespace)", "", "", {}),
        ("bare domain", "ca111.com", "ca111.com", {}),
        ("domain with leading/trailing whitespace", "  ca111.com  ", "ca111.com", {}),
        ("domain with mixed case", "Ca111.com", "Ca111.com", {}),
        ("domain with numeric labels", "1ca111.com", "1ca111.com", {}),
        ("domain with hyphenated labels", "c-a-111.com", "c-a-111.com", {}),
        ("domain with multiple labels", "sub.ca111.com", "sub.ca111.com", {}),
        ("domain followed by semicolon with no parameters", "ca111.com;", "ca111.com", {}),
        ("domain with single simple parameter", "ca111.com; policy=ev", "ca111.com", {"policy": "ev"}),
        ("domain with multiple parameters", "ca111.com; policy=ev;account=12345", "ca111.com", {"policy": "ev", "account": "12345"}),
        ("parameters with extra whitespace around separators", "ca111.com; policy = ev; account = 12345", "ca111.com", {"policy": "ev", "account": "12345"}),
        ("parameter tags with multiple consecutive dashes", "ca111.com; validation---method=http-01", "ca111.com", {"validation---method": "http-01"}),
        ("parameter values containing some special ASCII characters", "ca111.com; account=!@_[}#$z", "ca111.com", {"account": "!@_[}#$z"}),
        ("parameters without values", "ca111.com; policy=; account=12345", "ca111.com", {"policy": "", "account": "12345"}),  # why???
        ("parameters without domain", "; policy=ev", "", {"policy": "ev"}),
    ])
    # fmt: on
    def extract_domain_and_parameters_from_caa_value__should_parse_domain_and_parameters_given_well_formed_value(
        self, test_description, caa_value, expected_domain, expected_parameters
    ):
        domain, parameters = MpicCaaChecker.extract_domain_and_parameters_from_caa_value(caa_value)
        assert domain == expected_domain
        assert parameters == expected_parameters

    # fmt: off
    # noinspection PyUnusedLocal
    @pytest.mark.parametrize("test_description, caa_value", [
        ("rejects domain starting with dot", ".example.com"),
        ("rejects domain ending with dot", "ca111.com."),
        ("rejects domain with consecutive dots", "example..com"),
        ("rejects domain with invalid characters", "ex@mple.com!"),
        ("rejects domain labels starting with hyphen", "sub.-example.com"),
        ("rejects domain labels ending with hyphen", "example-.com"),
        ("rejects parameter tag starting with hyphen", "ca111.org; -policy=ev"),
        ("rejects parameter tag ending with hyphen", "ca111.org; policy-=ev"),
        ("rejects parameter without equals sign", "ca111.org; policy"),
        ("rejects parameter value containing semicolon", "ca111.org; policy=ev;account=12;345"),
        ("rejects parameter value containing control characters", "ca111.org; policy=ev;account=\x00"),
        ("rejects parameter tag with illegal characters", "ca111.org; queensrÿche=ev"),
        ("rejects parameter value with illegal characters in value", "ca111.org; policy=mötleycrüe"),
        ("rejects parameter tag containing space", "ca111.org; cool policy=ev"),
        ("rejects parameter value containing space", "ca111.org; policy=ev cool"),
        ("rejects trailing semicolon after parameter", "ca111.org; policy=ev;"),  # why???
        ("rejects malformed parameter separators", "ca111.org; policy=ev;;account=12345"),
    ])
    # fmt: on
    def extract_domain_and_parameters_from_caa_value__should_raise_error_given_malformed_value(
        self, test_description, caa_value
    ):
        # ABNF for CAA record value:
        #    issue-value = *WSP [issuer-domain-name *WSP] [";" *WSP [parameters *WSP]]
        #    issuer-domain-name = label *("." label)
        #    label = (ALPHA / DIGIT) *( *("-") (ALPHA / DIGIT))
        #    parameters = (parameter *WSP ";" *WSP parameters) / parameter
        #    parameter = tag *WSP "=" *WSP value
        #    tag = (ALPHA / DIGIT) *( *("-") (ALPHA / DIGIT))
        #    value = *(%x21-3A / %x3C-7E)
        with pytest.raises(ValueError) as error:
            MpicCaaChecker.extract_domain_and_parameters_from_caa_value(caa_value)

    # fmt: off
    # noinspection PyUnusedLocal
    @pytest.mark.parametrize("test_description, caa_values", [
        ("single matching record and no parameters present", ["ca111.org"]),
        ("multiple records with one match and no parameters present", ["ca111.org", "ca222.com"]),
        ("record with whitespace", ["  ca111.org  "]),
        ("record with mixed case in domain", ["Ca111.org"]),
        ("matching record with parameters that should be ignored", ["ca111.org; policy=ev; account=12345"]),
    ])
    # fmt: on
    def do_caa_values_permit_issuance__should_return_true_given_matching_well_formed_records(
        self, test_description, caa_values
    ):
        caa_domains = ["ca111.org", "ca333.net"]
        assert MpicCaaChecker.do_caa_values_permit_issuance(caa_values, caa_domains) is True

    # fmt: off
    # noinspection PyUnusedLocal
    @pytest.mark.parametrize("test_description, rrset_values", [
        ("empty record", [""]),
        ("empty record with semicolon only", [";"]),
        ("empty record with leading semicolon", [";policy=ev"]),
        ("single non-matching record and no parameters present", ["ca222.org"]),
        ("multiple records with no matches and no parameters present", ["ca333.net", "ca444.com"]),
        ("non-matching record with parameters that should be ignored", ["ca222.org; favorite-ca=ca111.org"]),
    ])
    # fmt: on
    def do_caa_values_permit_issuance__should_return_false_given_non_matching_well_formed_records(
        self, test_description, rrset_values
    ):
        caa_domains = ["ca111.org"]
        assert MpicCaaChecker.do_caa_values_permit_issuance(rrset_values, caa_domains) is False

    # fmt: off
    # noinspection PyUnusedLocal
    @pytest.mark.parametrize("test_description, rrset_values", [
        ("matching record with empty parameter", ["ca111.org; policy"]),
        ("matching record with illegal character in parameter", ["ca111.org; account=123föur5"]),
    ])
    # fmt: on
    def do_caa_values_permit_issuance__should_return_false_given_matching_but_malformed_records(
        self, test_description, rrset_values
    ):
        caa_domains = ["ca111.org"]
        assert MpicCaaChecker.do_caa_values_permit_issuance(rrset_values, caa_domains) is False

    def is_valid_for_issuance__should_be_true_given_matching_issue_tag_for_non_wildcard_domain(self):
        records = [MockDnsObjectCreator.create_caa_record(0, "issue", "ca1.org")]
        test_rrset = MockDnsObjectCreator.create_rrset(dns.rdatatype.CAA, *records)
        result = MpicCaaChecker.is_valid_for_issuance(
            caa_domains=["ca1.org"], certificate_type=CertificateType.TLS_SERVER, is_wc_domain=False, rrset=test_rrset
        )
        assert result is True

    def is_valid_for_issuance__should_be_true_given_matching_issue_tag_for_wildcard_domain(self):
        records = [MockDnsObjectCreator.create_caa_record(0, "issue", "ca1.org")]
        test_rrset = MockDnsObjectCreator.create_rrset(dns.rdatatype.CAA, *records)
        result = MpicCaaChecker.is_valid_for_issuance(
            caa_domains=["ca1.org"], certificate_type=CertificateType.TLS_SERVER, is_wc_domain=True, rrset=test_rrset
        )
        assert result is True

    def is_valid_for_issuance__should_be_true_given_matching_issuewild_tag_for_wildcard_domain(self):
        records = [
            MockDnsObjectCreator.create_caa_record(0, "issuewild", "ca1.org"),
            MockDnsObjectCreator.create_caa_record(0, "issue", "ca2.org"),
        ]
        test_rrset = MockDnsObjectCreator.create_rrset(dns.rdatatype.CAA, *records)
        result = MpicCaaChecker.is_valid_for_issuance(
            caa_domains=["ca1.org"], certificate_type=CertificateType.TLS_SERVER, is_wc_domain=True, rrset=test_rrset
        )
        assert result is True

    def is_valid_for_issuance__should_be_true_given_no_issue_tags_and_matching_issuewild_tag_for_wildcard_domain(self):
        records = [MockDnsObjectCreator.create_caa_record(0, "issuewild", "ca1.org")]
        test_rrset = MockDnsObjectCreator.create_rrset(dns.rdatatype.CAA, *records)
        result = MpicCaaChecker.is_valid_for_issuance(
            caa_domains=["ca1.org"], certificate_type=CertificateType.TLS_SERVER, is_wc_domain=True, rrset=test_rrset
        )
        assert result is True

    def is_valid_for_issuance__should_be_true_given_issuewild_disallowed_for_all_and_matching_issue_tag_found(self):
        records = [
            MockDnsObjectCreator.create_caa_record(0, "issue", "ca1.org"),
            MockDnsObjectCreator.create_caa_record(0, "issuewild", ";"),
        ]
        test_rrset = MockDnsObjectCreator.create_rrset(dns.rdatatype.CAA, *records)
        result = MpicCaaChecker.is_valid_for_issuance(
            caa_domains=["ca1.org"], certificate_type=CertificateType.TLS_SERVER, is_wc_domain=False, rrset=test_rrset
        )
        assert result is True

    def is_valid_for_issuance__should_be_true_given_no_issue_tags_found(self):
        records = [MockDnsObjectCreator.create_caa_record(0, "unknown", "ca1.org")]
        test_rrset = MockDnsObjectCreator.create_rrset(dns.rdatatype.CAA, *records)
        result = MpicCaaChecker.is_valid_for_issuance(
            caa_domains=["ca1.org"], certificate_type=CertificateType.TLS_SERVER, is_wc_domain=False, rrset=test_rrset
        )
        assert result is True

    @pytest.mark.parametrize("issue_tag", ["ISSUE", "IsSuE"])
    def is_valid_for_issuance__should_be_true_given_nonstandard_casing_in_issue_tag(self, issue_tag):
        records = [MockDnsObjectCreator.create_caa_record(0, issue_tag, "ca1.org")]
        test_rrset = MockDnsObjectCreator.create_rrset(dns.rdatatype.CAA, *records)
        result = MpicCaaChecker.is_valid_for_issuance(
            caa_domains=["ca1.org"], certificate_type=CertificateType.TLS_SERVER, is_wc_domain=False, rrset=test_rrset
        )
        assert result is True

    @pytest.mark.parametrize("known_tag", ["issue", "issuewild", "iodef", "issuemail", "contactemail", "contactphone"])
    def is_valid_for_issuance__should_be_true_given_critical_flag_and_known_tag(self, known_tag):
        records = [MockDnsObjectCreator.create_caa_record(128, known_tag, "ca1.org")]
        test_rrset = MockDnsObjectCreator.create_rrset(dns.rdatatype.CAA, *records)
        result = MpicCaaChecker.is_valid_for_issuance(
            caa_domains=["ca1.org"], certificate_type=CertificateType.TLS_SERVER, is_wc_domain=False, rrset=test_rrset
        )
        assert result is True

    def is_valid_for_issuance__should_be_true_given_restrictive_tag_alongside_matching_tag(self):
        records = [
            MockDnsObjectCreator.create_caa_record(0, "issue", "ca1.org"),
            MockDnsObjectCreator.create_caa_record(0, "issue", ";"),
        ]
        test_rrset = MockDnsObjectCreator.create_rrset(dns.rdatatype.CAA, *records)
        result = MpicCaaChecker.is_valid_for_issuance(
            caa_domains=["ca1.org"], certificate_type=CertificateType.TLS_SERVER, is_wc_domain=False, rrset=test_rrset
        )
        assert result is True

    @pytest.mark.parametrize("tag_value", [";", "ca5.org", ";policy=ev"])
    def is_valid_for_issuance__should_be_false_given_non_matching_or_restrictive_issue_tags(self, tag_value):
        records = [MockDnsObjectCreator.create_caa_record(0, "issue", tag_value)]
        test_rrset = MockDnsObjectCreator.create_rrset(dns.rdatatype.CAA, *records)
        result = MpicCaaChecker.is_valid_for_issuance(
            caa_domains=["ca1.org"], certificate_type=CertificateType.TLS_SERVER, is_wc_domain=False, rrset=test_rrset
        )
        assert result is False

    def is_valid_for_issuance__should_be_false_given_only_non_matching_issuewild_tags_for_wildcard_domain(self):
        records = [
            MockDnsObjectCreator.create_caa_record(0, "issuewild", "ca5.org"),
            MockDnsObjectCreator.create_caa_record(0, "issuewild", "ca6.org"),
        ]
        test_rrset = MockDnsObjectCreator.create_rrset(dns.rdatatype.CAA, *records)
        result = MpicCaaChecker.is_valid_for_issuance(
            caa_domains=["ca1.org"], certificate_type=CertificateType.TLS_SERVER, is_wc_domain=True, rrset=test_rrset
        )
        assert result is False

    def is_valid_for_issuance__should_be_false_given_critical_flag_for_an_unknown_tag(self):
        records = [
            MockDnsObjectCreator.create_caa_record(128, "mystery", "ca1.org"),
            MockDnsObjectCreator.create_caa_record(0, "issue", "ca1.org"),
        ]
        test_rrset = MockDnsObjectCreator.create_rrset(dns.rdatatype.CAA, *records)
        result = MpicCaaChecker.is_valid_for_issuance(
            caa_domains=["ca1.org"], certificate_type=CertificateType.TLS_SERVER, is_wc_domain=False, rrset=test_rrset
        )
        assert result is False

    def is_valid_for_issuance__should_be_false_given_issuewild_disallowed_for_all_and_wildcard_domain(self):
        records = [
            MockDnsObjectCreator.create_caa_record(0, "issue", "ca1.org"),
            MockDnsObjectCreator.create_caa_record(0, "issuewild", ";"),
        ]
        test_rrset = MockDnsObjectCreator.create_rrset(dns.rdatatype.CAA, *records)
        result = MpicCaaChecker.is_valid_for_issuance(
            caa_domains=["ca1.org"], certificate_type=CertificateType.TLS_SERVER, is_wc_domain=True, rrset=test_rrset
        )
        assert result is False

    def is_valid_for_issuance__should_be_false_given_attempted_xss_via_caa_record(self):
        records = [MockDnsObjectCreator.create_caa_record(0, "issue", 'ca1.org <script>alert("XSS")</script>')]
        test_rrset = MockDnsObjectCreator.create_rrset(dns.rdatatype.CAA, *records)
        result = MpicCaaChecker.is_valid_for_issuance(
            caa_domains=["ca1.org"], certificate_type=CertificateType.TLS_SERVER, is_wc_domain=False, rrset=test_rrset
        )
        assert result is False

    @pytest.mark.skip(reason="Checks for DNSSEC validity are not yet implemented")
    def is_valid_for_issuance__should_be_false_given_expired_dnssec_signature(self):
        records = [MockDnsObjectCreator.create_caa_record(0, "issue", "ca1.org")]
        test_rrset = MockDnsObjectCreator.create_rrset(dns.rdatatype.CAA, *records)
        result = MpicCaaChecker.is_valid_for_issuance(
            caa_domains=["ca1.org"], certificate_type=CertificateType.TLS_SERVER, is_wc_domain=False, rrset=test_rrset
        )
        assert result is False

    @pytest.mark.parametrize(
        "domain_1_tag, domain_1_value, expected_result",
        [("issue", ";", False), ("issue", "ca2.org", False), ("mystery", "ca2.org", True)],
    )
    def is_valid_for_issuance__should_ignore_issuewild_tags_given_non_wildcard_domain(
        self, domain_1_tag, domain_1_value, expected_result
    ):
        records = [
            MockDnsObjectCreator.create_caa_record(0, domain_1_tag, domain_1_value),
            MockDnsObjectCreator.create_caa_record(0, "issuewild", "ca1.org"),
        ]
        test_rrset = MockDnsObjectCreator.create_rrset(dns.rdatatype.CAA, *records)
        result = MpicCaaChecker.is_valid_for_issuance(
            caa_domains=["ca1.org"], certificate_type=CertificateType.TLS_SERVER, is_wc_domain=False, rrset=test_rrset
        )
        assert result is expected_result

    def is_valid_for_issuance__should_be_false_given_invalid_certificate_type(self):
        records = [MockDnsObjectCreator.create_caa_record(0, "issue", "ca1.org")]
        test_rrset = MockDnsObjectCreator.create_rrset(dns.rdatatype.CAA, *records)
        # noinspection PyTypeChecker
        result = MpicCaaChecker.is_valid_for_issuance(
            caa_domains=["ca1.org"], certificate_type="INVALID", is_wc_domain=False, rrset=test_rrset
        )
        assert result is False

    def raise_(self, ex):
        # noinspection PyUnusedLocal
        def _raise(*args, **kwargs):
            raise ex

        return _raise()

    def patch_resolver_resolve_with_side_effect(self, mocker, side_effect):
        return mocker.patch("dns.asyncresolver.resolve", new_callable=AsyncMock, side_effect=side_effect)

    def patch_resolver_with_answer_or_exception(self, mocker, mocked_answer_or_exception):
        # noinspection PyUnusedLocal
        async def side_effect(domain_name, rdtype):
            if isinstance(mocked_answer_or_exception, Exception):
                raise mocked_answer_or_exception
            return mocked_answer_or_exception

        return self.patch_resolver_resolve_with_side_effect(mocker, side_effect)

    def patch_resolver_to_expect_domain(self, mocker, expected_domain, mocked_answer, exception):
        # noinspection PyUnusedLocal
        async def side_effect(domain_name, rdtype):
            if domain_name.to_text() == expected_domain:
                return mocked_answer
            else:
                raise exception

        self.patch_resolver_resolve_with_side_effect(mocker, side_effect)

    def create_caa_check_request(self, domain_target, domain_list):
        return CaaCheckRequest(
            domain_or_ip_target=domain_target,
            caa_check_parameters=CaaCheckParameters(
                certificate_type=CertificateType.TLS_SERVER, caa_domains=domain_list
            ),
        )


if __name__ == "__main__":
    pytest.main()
