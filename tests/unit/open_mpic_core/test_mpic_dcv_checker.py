import asyncio
import base64
import logging
from io import StringIO
from typing import List

import dns
import pytest

from unittest.mock import MagicMock, AsyncMock
from yarl import URL
from asyncio import StreamReader
from aiohttp import ClientResponse
from aiohttp.client_exceptions import ClientConnectionError
from aiohttp.web import HTTPInternalServerError
from multidict import CIMultiDictProxy, CIMultiDict
from dns.rcode import Rcode

from open_mpic_core import (
    DcvCheckRequest,
    DcvValidationMethod,
    DnsRecordType,
    MpicValidationError,
    MpicDcvChecker,
    TRACE_LEVEL,
)

from unit.test_util.mock_dns_object_creator import MockDnsObjectCreator
from unit.test_util.valid_check_creator import ValidCheckCreator


# noinspection PyMethodMayBeStatic
class TestMpicDcvChecker:
    # noinspection PyAttributeOutsideInit
    @pytest.fixture(autouse=True)
    def setup_dcv_checker(self) -> MpicDcvChecker:
        self.dcv_checker = MpicDcvChecker("us-east-4")
        yield self.dcv_checker

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

    def constructor__should_set_log_level_if_provided(self):
        dcv_checker = MpicDcvChecker("us-east-4", log_level=logging.ERROR)
        assert dcv_checker.logger.level == logging.ERROR

    def mpic_dcv_checker__should_be_able_to_log_at_trace_level(self):
        dcv_checker = MpicDcvChecker("us-east-4", log_level=TRACE_LEVEL)
        test_message = "This is a trace log message."
        dcv_checker.logger.trace(test_message)
        log_contents = self.log_output.getvalue()
        assert all(text in log_contents for text in [test_message, "TRACE", dcv_checker.logger.name])

    @pytest.mark.parametrize("reuse_http_client", [True, False])
    async def mpic_dcv_checker__should_optionally_reuse_http_client(self, reuse_http_client):
        dcv_checker = MpicDcvChecker("us-east-4", reuse_http_client=reuse_http_client, log_level=TRACE_LEVEL)
        async with dcv_checker.get_async_http_client() as client_1:
            async with dcv_checker.get_async_http_client() as client_2:
                try:
                    assert (client_1 is client_2) == reuse_http_client
                finally:
                    if reuse_http_client:
                        await dcv_checker.shutdown()

    # integration test of a sort -- only mocking dns methods rather than remaining class methods
    @pytest.mark.parametrize(
        "validation_method, record_type",
        [
            (DcvValidationMethod.WEBSITE_CHANGE_V2, None),
            (DcvValidationMethod.DNS_CHANGE, DnsRecordType.TXT),
            (DcvValidationMethod.DNS_CHANGE, DnsRecordType.CNAME),
            (DcvValidationMethod.DNS_CHANGE, DnsRecordType.CAA),
            (DcvValidationMethod.CONTACT_EMAIL, DnsRecordType.TXT),
            (DcvValidationMethod.CONTACT_EMAIL, DnsRecordType.CAA),
            (DcvValidationMethod.CONTACT_PHONE, DnsRecordType.TXT),
            (DcvValidationMethod.CONTACT_PHONE, DnsRecordType.CAA),
            (DcvValidationMethod.IP_LOOKUP, DnsRecordType.A),
            (DcvValidationMethod.IP_LOOKUP, DnsRecordType.AAAA),
            (DcvValidationMethod.ACME_HTTP_01, None),
            (DcvValidationMethod.ACME_DNS_01, None),
        ],
    )
    async def check_dcv__should_perform_appropriate_check_and_allow_issuance_given_target_record_found(
        self, validation_method, record_type, mocker
    ):
        dcv_request = None
        match validation_method:
            case DcvValidationMethod.WEBSITE_CHANGE_V2 | DcvValidationMethod.ACME_HTTP_01:
                dcv_request = ValidCheckCreator.create_valid_dcv_check_request(validation_method)
            case DcvValidationMethod.DNS_CHANGE:
                dcv_request = ValidCheckCreator.create_valid_dns_check_request(record_type)
            case DcvValidationMethod.CONTACT_EMAIL | DcvValidationMethod.CONTACT_PHONE:
                dcv_request = ValidCheckCreator.create_valid_dcv_check_request(validation_method, record_type)
            case DcvValidationMethod.IP_LOOKUP:
                dcv_request = ValidCheckCreator.create_valid_ip_lookup_check_request(record_type)
            case DcvValidationMethod.ACME_DNS_01:
                dcv_request = ValidCheckCreator.create_valid_dcv_check_request(validation_method)
        if (
            validation_method == DcvValidationMethod.WEBSITE_CHANGE_V2
            or validation_method == DcvValidationMethod.ACME_HTTP_01
        ):
            self.mock_request_specific_http_response(dcv_request, mocker)
        else:
            self.mock_request_specific_dns_resolve_call(dcv_request, mocker)
        dcv_response = await self.dcv_checker.check_dcv(dcv_request)
        dcv_response.timestamp_ns = None  # ignore timestamp for comparison
        assert dcv_response.check_passed is True

    @pytest.mark.parametrize(
        "validation_method, domain, encoded_domain",
        [
            (DcvValidationMethod.WEBSITE_CHANGE_V2, "bücher.example.de", "xn--bcher-kva.example.de"),
            (DcvValidationMethod.ACME_DNS_01, "café.com", "xn--caf-dma.com"),
        ],
    )
    async def check_dcv__should_handle_domains_with_non_ascii_characters(
        self, validation_method, domain, encoded_domain, mocker
    ):
        if validation_method == DcvValidationMethod.WEBSITE_CHANGE_V2:
            dcv_request = ValidCheckCreator.create_valid_dcv_check_request(validation_method)
            dcv_request.domain_or_ip_target = encoded_domain  # do this first for mocking
            self.mock_request_specific_http_response(dcv_request, mocker)
        else:
            dcv_request = ValidCheckCreator.create_valid_dcv_check_request(validation_method)
            dcv_request.domain_or_ip_target = encoded_domain  # do this first for mocking
            self.mock_request_specific_dns_resolve_call(dcv_request, mocker)

        dcv_request.domain_or_ip_target = domain  # set to original to see if the mock triggers as expected
        dcv_response = await self.dcv_checker.check_dcv(dcv_request)
        assert dcv_response.check_passed is True

    @pytest.mark.parametrize("validation_method", [DcvValidationMethod.ACME_HTTP_01, DcvValidationMethod.ACME_DNS_01])
    async def check_dcv__should_be_able_to_trace_timing_of_http_and_dns_lookups(self, validation_method, mocker):
        tracing_dcv_checker = MpicDcvChecker("us-east-4", log_level=TRACE_LEVEL)

        if validation_method == DcvValidationMethod.ACME_HTTP_01:
            dcv_request = ValidCheckCreator.create_valid_dcv_check_request(validation_method)
            self.mock_request_specific_http_response(dcv_request, mocker)
        else:
            dcv_request = ValidCheckCreator.create_valid_dcv_check_request(validation_method)
            self.mock_request_specific_dns_resolve_call(dcv_request, mocker)

        await tracing_dcv_checker.check_dcv(dcv_request)
        log_contents = self.log_output.getvalue()
        assert all(text in log_contents for text in ["seconds", "TRACE", tracing_dcv_checker.logger.name])

    @pytest.mark.parametrize(
        "validation_method", [DcvValidationMethod.WEBSITE_CHANGE_V2, DcvValidationMethod.ACME_HTTP_01]
    )
    async def http_based_dcv_checks__should_return_check_success_given_token_file_found_with_expected_content(
        self, validation_method, mocker
    ):
        dcv_request = ValidCheckCreator.create_valid_dcv_check_request(validation_method)
        self.mock_request_specific_http_response(dcv_request, mocker)
        dcv_response = await self.dcv_checker.check_dcv(dcv_request)
        assert dcv_response.check_passed is True

    @pytest.mark.parametrize(
        "validation_method", [DcvValidationMethod.WEBSITE_CHANGE_V2, DcvValidationMethod.ACME_HTTP_01]
    )
    async def http_based_dcv_checks__should_return_timestamp_and_response_url_and_status_code(
        self, validation_method, mocker
    ):
        dcv_request = ValidCheckCreator.create_valid_dcv_check_request(validation_method)
        self.mock_request_specific_http_response(dcv_request, mocker)
        dcv_response = await self.dcv_checker.check_dcv(dcv_request)
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

    @pytest.mark.parametrize(
        "validation_method", [DcvValidationMethod.WEBSITE_CHANGE_V2, DcvValidationMethod.ACME_HTTP_01]
    )
    async def http_based_dcv_checks__should_return_check_failure_given_token_file_not_found(
        self, validation_method, mocker
    ):
        fail_response = TestMpicDcvChecker.create_mock_http_response(404, "Not Found", {"reason": "Not Found"})
        self.mock_request_agnostic_http_response(fail_response, mocker)
        dcv_request = ValidCheckCreator.create_valid_dcv_check_request(validation_method)
        dcv_response = await self.dcv_checker.check_dcv(dcv_request)
        assert dcv_response.check_passed is False

    @pytest.mark.parametrize(
        "validation_method", [DcvValidationMethod.WEBSITE_CHANGE_V2, DcvValidationMethod.ACME_HTTP_01]
    )
    async def http_based_dcv_checks__should_return_error_details_given_token_file_not_found(
        self, validation_method, mocker
    ):
        fail_response = TestMpicDcvChecker.create_mock_http_response(404, "Not Found", {"reason": "Not Found"})
        self.mock_request_agnostic_http_response(fail_response, mocker)
        dcv_request = ValidCheckCreator.create_valid_dcv_check_request(validation_method)
        dcv_response = await self.dcv_checker.check_dcv(dcv_request)
        assert dcv_response.check_passed is False
        assert dcv_response.timestamp_ns is not None
        errors = [MpicValidationError(error_type="404", error_message="Not Found")]
        assert dcv_response.errors == errors

    @pytest.mark.parametrize(
        "validation_method, exception, error_message",
        [
            (DcvValidationMethod.WEBSITE_CHANGE_V2, HTTPInternalServerError(reason="Test Exception"), "Test Exception"),
            (DcvValidationMethod.ACME_HTTP_01, ClientConnectionError(), ""),
        ],
    )
    async def http_based_dcv_checks__should_return_check_failure_and_error_details_given_exception_raised(
        self, validation_method, exception, error_message, mocker
    ):
        mocker.patch("aiohttp.ClientSession.get", side_effect=exception)
        dcv_request = ValidCheckCreator.create_valid_dcv_check_request(validation_method)
        dcv_response = await self.dcv_checker.check_dcv(dcv_request)
        assert dcv_response.check_passed is False
        errors = [MpicValidationError(error_type=exception.__class__.__name__, error_message=error_message)]
        assert dcv_response.errors == errors

    @pytest.mark.parametrize(
        "validation_method", [DcvValidationMethod.WEBSITE_CHANGE_V2, DcvValidationMethod.ACME_HTTP_01]
    )
    async def http_based_dcv_checks__should_return_check_failure_given_non_matching_response_content(
        self, validation_method, mocker
    ):
        dcv_request = ValidCheckCreator.create_valid_dcv_check_request(validation_method)
        self.mock_request_specific_http_response(dcv_request, mocker)
        if validation_method == DcvValidationMethod.WEBSITE_CHANGE_V2:
            dcv_request.dcv_check_parameters.validation_details.challenge_value = "expecting-this-value-now-instead"
        else:
            dcv_request.dcv_check_parameters.validation_details.key_authorization = "expecting-this-value-now-instead"
        dcv_response = await self.dcv_checker.check_dcv(dcv_request)
        assert dcv_response.check_passed is False

    @pytest.mark.parametrize(
        "validation_method, expected_segment",
        [
            (DcvValidationMethod.WEBSITE_CHANGE_V2, ".well-known/pki-validation"),
            (DcvValidationMethod.ACME_HTTP_01, ".well-known/acme-challenge"),
        ],
    )
    async def http_based_dcv_checks__should_auto_insert_well_known_path_segment(
        self, validation_method, expected_segment, mocker
    ):
        dcv_request = ValidCheckCreator.create_valid_dcv_check_request(validation_method)
        match validation_method:
            case DcvValidationMethod.WEBSITE_CHANGE_V2:
                dcv_request.dcv_check_parameters.validation_details.http_token_path = "test-path"
                url_scheme = dcv_request.dcv_check_parameters.validation_details.url_scheme
            case _:
                dcv_request.dcv_check_parameters.validation_details.token = "test-path"
                url_scheme = "http"
        self.mock_request_specific_http_response(dcv_request, mocker)
        dcv_response = await self.dcv_checker.check_dcv(dcv_request)
        expected_url = f"{url_scheme}://{dcv_request.domain_or_ip_target}/{expected_segment}/test-path"
        assert dcv_response.details.response_url == expected_url

    @pytest.mark.parametrize(
        "validation_method", [DcvValidationMethod.WEBSITE_CHANGE_V2, DcvValidationMethod.ACME_HTTP_01]
    )
    async def http_based_dcv_checks__should_follow_redirects_and_track_redirect_history_in_details(
        self, validation_method, mocker
    ):
        dcv_request = ValidCheckCreator.create_valid_dcv_check_request(validation_method)
        match dcv_request.dcv_check_parameters.validation_details.validation_method:
            case DcvValidationMethod.WEBSITE_CHANGE_V2:
                expected_challenge = dcv_request.dcv_check_parameters.validation_details.challenge_value
            case _:
                expected_challenge = dcv_request.dcv_check_parameters.validation_details.key_authorization

        history = self.create_http_redirect_history()
        mock_response = TestMpicDcvChecker.create_mock_http_response(200, expected_challenge, {"history": history})
        self.mock_request_agnostic_http_response(mock_response, mocker)
        dcv_response = await self.dcv_checker.check_dcv(dcv_request)
        redirects = dcv_response.details.response_history
        assert len(redirects) == 2
        assert redirects[0].url == "https://example.com/redirected-1"
        assert redirects[0].status_code == 301
        assert redirects[1].url == "https://example.com/redirected-2"
        assert redirects[1].status_code == 302

    @pytest.mark.parametrize(
        "validation_method", [DcvValidationMethod.WEBSITE_CHANGE_V2, DcvValidationMethod.ACME_HTTP_01]
    )
    async def http_based_dcv_checks__should_include_base64_encoded_response_page_in_details(
        self, validation_method, mocker
    ):
        dcv_request = ValidCheckCreator.create_valid_dcv_check_request(validation_method)
        mock_response = TestMpicDcvChecker.create_mock_http_response_with_content_and_encoding(b"aaa", "utf-8")
        self.mock_request_agnostic_http_response(mock_response, mocker)
        dcv_response = await self.dcv_checker.check_dcv(dcv_request)
        assert dcv_response.details.response_page == base64.b64encode(b"aaa").decode()

    @pytest.mark.parametrize(
        "validation_method", [DcvValidationMethod.WEBSITE_CHANGE_V2, DcvValidationMethod.ACME_HTTP_01]
    )
    async def http_based_dcv_checks__should_include_up_to_first_100_bytes_of_returned_content_in_details(
        self, validation_method, mocker
    ):
        dcv_request = ValidCheckCreator.create_valid_dcv_check_request(validation_method)
        mock_response = TestMpicDcvChecker.create_mock_http_response_with_content_and_encoding(b"a" * 1000, "utf-8")
        self.mock_request_agnostic_http_response(mock_response, mocker)
        dcv_response = await self.dcv_checker.check_dcv(dcv_request)
        hundred_a_chars_b64 = base64.b64encode(
            b"a" * 100
        ).decode()  # store 100 'a' characters in a base64 encoded string
        assert dcv_response.details.response_page == hundred_a_chars_b64

    async def http_based_dcv_checks__should_read_more_than_100_bytes_if_challenge_value_requires_it(self, mocker):
        dcv_request = ValidCheckCreator.create_valid_dcv_check_request(DcvValidationMethod.WEBSITE_CHANGE_V2)
        dcv_request.dcv_check_parameters.validation_details.challenge_value = "".join(["a"] * 150)  # 150 'a' characters
        mock_response = TestMpicDcvChecker.create_mock_http_response_with_content_and_encoding(b"a" * 1000, "utf-8")
        self.mock_request_agnostic_http_response(mock_response, mocker)
        dcv_response = await self.dcv_checker.check_dcv(dcv_request)
        hundred_fifty_a_chars_b64 = base64.b64encode(b"a" * 150).decode()  # store 150 chars in base64 encoded string
        assert len(dcv_response.details.response_page) == len(hundred_fifty_a_chars_b64)

    @pytest.mark.parametrize(
        "validation_method", [DcvValidationMethod.WEBSITE_CHANGE_V2, DcvValidationMethod.ACME_HTTP_01]
    )
    async def http_based_dcv_checks__should_leverage_requests_decoding_capabilities(self, validation_method, mocker):
        # Expected to be received in the Content-Type header.
        # "Café" in ISO-8859-1 is chosen as it is different, for example, when UTF-8 encoded: "43 61 66 C3 A9"
        encoding = "ISO-8859-1"
        content = b"\x43\x61\x66\xE9"
        expected_challenge_value = "Café"

        dcv_request = ValidCheckCreator.create_valid_dcv_check_request(validation_method)
        mock_response = TestMpicDcvChecker.create_mock_http_response_with_content_and_encoding(content, encoding)
        self.mock_request_agnostic_http_response(mock_response, mocker)
        match validation_method:
            case DcvValidationMethod.WEBSITE_CHANGE_V2:
                dcv_request.dcv_check_parameters.validation_details.challenge_value = expected_challenge_value
            case DcvValidationMethod.ACME_HTTP_01:
                dcv_request.dcv_check_parameters.validation_details.key_authorization = expected_challenge_value
        dcv_response = await self.dcv_checker.check_dcv(dcv_request)
        assert dcv_response.check_passed is True

    @pytest.mark.parametrize(
        "validation_method", [DcvValidationMethod.WEBSITE_CHANGE_V2, DcvValidationMethod.ACME_HTTP_01]
    )
    async def http_based_dcv_checks__should_utilize_custom_http_headers_if_provided_in_request(
        self, validation_method, mocker
    ):
        dcv_request = ValidCheckCreator.create_valid_dcv_check_request(validation_method)
        headers = {
            "X-Test-Header": "test-value",
            "User-Agent": "test-agent",
        }
        dcv_request.dcv_check_parameters.validation_details.http_headers = headers
        requests_get_mock = self.mock_request_specific_http_response(dcv_request, mocker)
        await self.dcv_checker.check_dcv(dcv_request)

        assert requests_get_mock.call_args.kwargs["headers"] == headers

    @pytest.mark.parametrize("url_scheme", ["http", "https"])
    async def website_change_v2_validation__should_use_specified_url_scheme(self, url_scheme, mocker):
        dcv_request = ValidCheckCreator.create_valid_http_check_request()
        dcv_request.dcv_check_parameters.validation_details.url_scheme = url_scheme
        self.mock_request_specific_http_response(dcv_request, mocker)
        dcv_response = await self.dcv_checker.perform_http_based_validation(dcv_request)
        assert dcv_response.check_passed is True
        assert dcv_response.details.response_url.startswith(f"{url_scheme}://")

    @pytest.mark.parametrize(
        "challenge_value, check_passed",
        [("eXtRaStUfFchallenge-valueMoReStUfF", True), ("eXtRaStUfFchallenge-bad-valueMoReStUfF", False)],
    )
    async def website_change_v2_validation__should_use_substring_matching_for_challenge_value(
        self, challenge_value, check_passed, mocker
    ):
        dcv_request = ValidCheckCreator.create_valid_http_check_request()
        dcv_request.dcv_check_parameters.validation_details.challenge_value = challenge_value
        self.mock_request_specific_http_response(dcv_request, mocker)
        dcv_request.dcv_check_parameters.validation_details.challenge_value = "challenge-value"
        dcv_response = await self.dcv_checker.perform_http_based_validation(dcv_request)
        assert dcv_response.check_passed is check_passed

    async def website_change_v2_validation__should_set_is_valid_true_with_regex_match(self, mocker):
        dcv_request = ValidCheckCreator.create_valid_http_check_request()
        dcv_request.dcv_check_parameters.validation_details.match_regex = "^challenge_[0-9]*$"
        self.mock_request_specific_http_response(dcv_request, mocker)
        dcv_response = await self.dcv_checker.perform_http_based_validation(dcv_request)
        assert dcv_response.check_passed is True

    async def website_change_v2_validation__should_set_is_valid_false_with_regex_not_matching(self, mocker):
        dcv_request = ValidCheckCreator.create_valid_http_check_request()
        dcv_request.dcv_check_parameters.validation_details.match_regex = "^challenge_[2-9]*$"
        self.mock_request_specific_http_response(dcv_request, mocker)
        dcv_response = await self.dcv_checker.perform_http_based_validation(dcv_request)
        assert dcv_response.check_passed is False

    @pytest.mark.parametrize(
        "key_authorization, check_passed", [("challenge_111", True), ("eXtRaStUfFchallenge_111MoReStUfF", False)]
    )
    async def acme_http_01_validation__should_use_exact_matching_for_challenge_value(
        self, key_authorization, check_passed, mocker
    ):
        dcv_request = ValidCheckCreator.create_valid_acme_http_01_check_request()
        dcv_request.dcv_check_parameters.validation_details.key_authorization = key_authorization
        self.mock_request_specific_http_response(dcv_request, mocker)
        dcv_request.dcv_check_parameters.validation_details.key_authorization = "challenge_111"
        dcv_response = await self.dcv_checker.perform_http_based_validation(dcv_request)
        assert dcv_response.check_passed is check_passed

    @pytest.mark.parametrize("record_type", [DnsRecordType.TXT, DnsRecordType.CNAME])
    async def dns_validation__should_return_check_success_given_expected_dns_record_found(self, record_type, mocker):
        dcv_request = ValidCheckCreator.create_valid_dns_check_request(record_type)
        self.mock_request_specific_dns_resolve_call(dcv_request, mocker)
        dcv_response = await self.dcv_checker.perform_general_dns_validation(dcv_request)
        assert dcv_response.check_passed is True

    async def dns_validation__should_be_case_insensitive_for_cname_records(self, mocker):
        dcv_request = ValidCheckCreator.create_valid_dns_check_request(DnsRecordType.CNAME)
        dcv_request.dcv_check_parameters.validation_details.challenge_value = "CNAME-VALUE"
        self.mock_request_specific_dns_resolve_call(dcv_request, mocker)
        dcv_request.dcv_check_parameters.validation_details.challenge_value = "cname-value"
        dcv_response = await self.dcv_checker.perform_general_dns_validation(dcv_request)
        assert dcv_response.check_passed is True

    async def dns_validation__should_allow_finding_expected_challenge_as_substring_by_default(self, mocker):
        dcv_request = ValidCheckCreator.create_valid_dcv_check_request(DcvValidationMethod.DNS_CHANGE)
        dcv_request.dcv_check_parameters.validation_details.challenge_value = "eXtRaStUfFchallenge-valueMoReStUfF"
        self.mock_request_specific_dns_resolve_call(dcv_request, mocker)
        dcv_request.dcv_check_parameters.validation_details.challenge_value = "challenge-value"
        dcv_response = await self.dcv_checker.perform_general_dns_validation(dcv_request)
        assert dcv_response.check_passed is True

    async def dns_validation__should_allow_finding_expected_challenge_exactly_if_specified(self, mocker):
        dcv_request = ValidCheckCreator.create_valid_dcv_check_request(DcvValidationMethod.DNS_CHANGE)
        dcv_request.dcv_check_parameters.validation_details.challenge_value = "challenge-value"
        self.mock_request_specific_dns_resolve_call(dcv_request, mocker)
        dcv_request.dcv_check_parameters.validation_details.require_exact_match = True
        dcv_response = await self.dcv_checker.perform_general_dns_validation(dcv_request)
        assert dcv_response.check_passed is True

    @pytest.mark.parametrize("dns_name_prefix", ["_dnsauth", "", None])
    async def dns_validation__should_use_dns_name_prefix_if_provided(self, dns_name_prefix, mocker):
        dcv_request = ValidCheckCreator.create_valid_dns_check_request()
        dcv_request.dcv_check_parameters.validation_details.dns_name_prefix = dns_name_prefix
        mock_dns_resolver_resolve = self.mock_request_specific_dns_resolve_call(dcv_request, mocker)
        dcv_response = await self.dcv_checker.perform_general_dns_validation(dcv_request)
        assert dcv_response.check_passed is True
        if dns_name_prefix is not None and len(dns_name_prefix) > 0:
            mock_dns_resolver_resolve.assert_called_once_with(
                f"{dns_name_prefix}.{dcv_request.domain_or_ip_target}", dns.rdatatype.TXT
            )
        else:
            mock_dns_resolver_resolve.assert_called_once_with(dcv_request.domain_or_ip_target, dns.rdatatype.TXT)

    async def acme_dns_validation__should_auto_insert_acme_challenge_prefix(self, mocker):
        dcv_request = ValidCheckCreator.create_valid_acme_dns_01_check_request()
        mock_dns_resolver_resolve = self.mock_request_specific_dns_resolve_call(dcv_request, mocker)
        dcv_response = await self.dcv_checker.perform_general_dns_validation(dcv_request)
        assert dcv_response.check_passed is True
        mock_dns_resolver_resolve.assert_called_once_with(
            f"_acme-challenge.{dcv_request.domain_or_ip_target}", dns.rdatatype.TXT
        )

    async def contact_email_txt_lookup__should_auto_insert_validation_prefix(self, mocker):
        dcv_request = ValidCheckCreator.create_valid_contact_check_request(
            DcvValidationMethod.CONTACT_EMAIL, DnsRecordType.TXT
        )
        mock_dns_resolver_resolve = self.mock_request_specific_dns_resolve_call(dcv_request, mocker)
        dcv_response = await self.dcv_checker.perform_general_dns_validation(dcv_request)
        assert dcv_response.check_passed is True
        mock_dns_resolver_resolve.assert_called_once_with(
            f"_validation-contactemail.{dcv_request.domain_or_ip_target}", dns.rdatatype.TXT
        )

    async def contact_phone_txt_lookup__should_auto_insert_validation_prefix(self, mocker):
        dcv_request = ValidCheckCreator.create_valid_contact_check_request(
            DcvValidationMethod.CONTACT_PHONE, DnsRecordType.TXT
        )
        mock_dns_resolver_resolve = self.mock_request_specific_dns_resolve_call(dcv_request, mocker)
        dcv_response = await self.dcv_checker.perform_general_dns_validation(dcv_request)
        assert dcv_response.check_passed is True
        mock_dns_resolver_resolve.assert_called_once_with(
            f"_validation-contactphone.{dcv_request.domain_or_ip_target}", dns.rdatatype.TXT
        )

    @pytest.mark.parametrize(
        "validation_method, tag, expected_result",
        [
            (DcvValidationMethod.CONTACT_EMAIL, "issue", False),
            (DcvValidationMethod.CONTACT_EMAIL, "contactemail", True),
            (DcvValidationMethod.CONTACT_PHONE, "issue", False),
            (DcvValidationMethod.CONTACT_PHONE, "contactphone", True),
        ],
    )
    async def contact_info_caa_lookup__should_fail_if_required_tag_not_found(
        self, validation_method, tag, expected_result, mocker
    ):
        dcv_request = ValidCheckCreator.create_valid_contact_check_request(validation_method, DnsRecordType.CAA)
        dcv_details = dcv_request.dcv_check_parameters.validation_details
        # should be contactemail, contactphone
        record_data = {"flags": 0, "tag": tag, "value": dcv_details.challenge_value}
        test_dns_query_answer = MockDnsObjectCreator.create_dns_query_answer(
            dcv_request.domain_or_ip_target, dcv_details.dns_name_prefix, DnsRecordType.CAA, record_data, mocker
        )
        self.patch_resolver_with_answer_or_exception(mocker, test_dns_query_answer)
        dcv_response = await self.dcv_checker.perform_general_dns_validation(dcv_request)
        assert dcv_response.check_passed is expected_result

    @pytest.mark.parametrize(
        "validation_method", [DcvValidationMethod.CONTACT_EMAIL, DcvValidationMethod.CONTACT_PHONE]
    )
    async def contact_info_caa_lookup__should_climb_domain_tree_to_find_records_and_include_domain_with_found_record_in_details(
        self, validation_method, mocker
    ):
        dcv_request = ValidCheckCreator.create_valid_contact_check_request(validation_method, DnsRecordType.CAA)
        self.mock_request_specific_dns_resolve_call(dcv_request, mocker)
        current_target = dcv_request.domain_or_ip_target
        dcv_request.domain_or_ip_target = f"sub2.sub1.{current_target}"
        dcv_response = await self.dcv_checker.perform_general_dns_validation(dcv_request)
        assert dcv_response.check_passed is True
        assert dcv_response.details.found_at == current_target

    @pytest.mark.parametrize("validation_method", [DcvValidationMethod.DNS_CHANGE, DcvValidationMethod.ACME_DNS_01])
    async def dns_based_dcv_checks__should_return_check_failure_given_non_matching_dns_record(
        self, validation_method, mocker
    ):
        dcv_request = ValidCheckCreator.create_valid_dcv_check_request(validation_method)
        test_dns_query_answer = self.create_basic_dns_response_for_mock(dcv_request, mocker)
        test_dns_query_answer.response.answer[0].items.clear()
        test_dns_query_answer.response.answer[0].add(
            MockDnsObjectCreator.create_record_by_type(DnsRecordType.TXT, {"value": "not-the-expected-value"})
        )
        self.patch_resolver_with_answer_or_exception(mocker, test_dns_query_answer)
        dcv_response = await self.dcv_checker.check_dcv(dcv_request)
        assert dcv_response.check_passed is False

    @pytest.mark.parametrize("validation_method", [DcvValidationMethod.DNS_CHANGE, DcvValidationMethod.ACME_DNS_01])
    async def dns_based_dcv_checks__should_return_timestamp_and_list_of_records_seen(self, validation_method, mocker):
        dcv_request = ValidCheckCreator.create_valid_dcv_check_request(validation_method)
        self.mock_dns_resolve_call_getting_multiple_txt_records(dcv_request, mocker)
        dcv_response = await self.dcv_checker.check_dcv(dcv_request)
        if validation_method == DcvValidationMethod.DNS_CHANGE:
            expected_value_1 = dcv_request.dcv_check_parameters.validation_details.challenge_value
        else:
            expected_value_1 = dcv_request.dcv_check_parameters.validation_details.key_authorization
        assert dcv_response.timestamp_ns is not None
        expected_records = [expected_value_1, "whatever2", "whatever3"]
        assert dcv_response.details.records_seen == expected_records

    @pytest.mark.parametrize(
        "validation_method, response_code",
        [
            (DcvValidationMethod.DNS_CHANGE, Rcode.NOERROR),
            (DcvValidationMethod.ACME_DNS_01, Rcode.NXDOMAIN),
            (DcvValidationMethod.DNS_CHANGE, Rcode.REFUSED),
        ],
    )
    async def dns_based_dcv_checks__should_return_response_code(self, validation_method, response_code, mocker):
        dcv_request = ValidCheckCreator.create_valid_dcv_check_request(validation_method)
        self.mock_dns_resolve_call_with_specific_response_code(dcv_request, response_code, mocker)
        dcv_response = await self.dcv_checker.check_dcv(dcv_request)
        assert dcv_response.details.response_code == response_code

    @pytest.mark.parametrize(
        "validation_method, flag, flag_set",
        [
            (DcvValidationMethod.DNS_CHANGE, dns.flags.AD, True),
            (DcvValidationMethod.DNS_CHANGE, dns.flags.CD, False),
            (DcvValidationMethod.ACME_DNS_01, dns.flags.AD, True),
            (DcvValidationMethod.ACME_DNS_01, dns.flags.CD, False),
        ],
    )
    async def dns_based_dcv_checks__should_return_whether_response_has_ad_flag(
        self, validation_method, flag, flag_set, mocker
    ):
        dcv_request = ValidCheckCreator.create_valid_dcv_check_request(validation_method)
        self.mock_dns_resolve_call_with_specific_flag(dcv_request, flag, mocker)
        dcv_response = await self.dcv_checker.check_dcv(dcv_request)
        assert dcv_response.details.ad_flag is flag_set

    @pytest.mark.parametrize("validation_method", [DcvValidationMethod.DNS_CHANGE, DcvValidationMethod.ACME_DNS_01])
    async def dns_based_dcv_checks__should_return_check_failure_with_errors_given_exception_raised(
        self, validation_method, mocker
    ):
        dcv_request = ValidCheckCreator.create_valid_dcv_check_request(validation_method)
        no_answer_error = dns.resolver.NoAnswer()
        self.patch_resolver_with_answer_or_exception(mocker, no_answer_error)
        dcv_response = await self.dcv_checker.check_dcv(dcv_request)
        errors = [MpicValidationError(error_type=no_answer_error.__class__.__name__, error_message=no_answer_error.msg)]
        assert dcv_response.check_passed is False
        assert dcv_response.errors == errors

    def raise_(self, ex):
        # noinspection PyUnusedLocal
        def _raise(*args, **kwargs):
            raise ex

        return _raise()

    @staticmethod
    def create_base_client_response_for_mock(event_loop):
        return ClientResponse(
            method="GET",
            url=URL("http://example.com"),
            writer=MagicMock(),
            continue100=None,
            timer=AsyncMock(),
            request_info=AsyncMock(),
            traces=[],
            loop=event_loop,
            session=AsyncMock(),
        )

    @staticmethod
    def create_mock_http_response(status_code: int, content: str, kwargs: dict = None):
        event_loop = asyncio.get_event_loop()
        response = TestMpicDcvChecker.create_base_client_response_for_mock(event_loop)
        response.status = status_code

        default_headers = {"Content-Type": "text/plain; charset=utf-8", "Content-Length": str(len(content))}
        response.content = StreamReader(loop=event_loop)
        response.content.feed_data(bytes(content.encode("utf-8")))
        response.content.feed_eof()

        additional_headers = {}
        if kwargs is not None:
            if "reason" in kwargs:
                response.reason = kwargs["reason"]
            if "history" in kwargs:
                response._history = kwargs["history"]
            additional_headers = kwargs.get("headers", {})

        all_headers = {**default_headers, **additional_headers}
        response._headers = CIMultiDictProxy(CIMultiDict(all_headers))

        return response

    @staticmethod
    def create_mock_http_redirect_response(status_code: int, redirect_url: str):
        event_loop = asyncio.get_event_loop()
        response = TestMpicDcvChecker.create_base_client_response_for_mock(event_loop)
        response.status = status_code
        response._headers = CIMultiDictProxy(CIMultiDict({"Location": redirect_url}))
        return response

    @staticmethod
    def create_mock_http_response_with_content_and_encoding(content: bytes, encoding: str):
        event_loop = asyncio.get_event_loop()
        response = TestMpicDcvChecker.create_base_client_response_for_mock(event_loop)
        response.status = 200
        response._headers = CIMultiDictProxy(CIMultiDict({"Content-Type": f"text/plain; charset={encoding}"}))
        response.content = StreamReader(loop=event_loop)
        response.content.feed_data(content)
        response.content.feed_eof()
        return response

    def mock_request_specific_http_response(self, dcv_request: DcvCheckRequest, mocker):
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

        success_response = TestMpicDcvChecker.create_mock_http_response(200, expected_challenge)
        not_found_response = TestMpicDcvChecker.create_mock_http_response(404, "Not Found", {"reason": "Not Found"})

        # noinspection PyProtectedMember
        return mocker.patch(
            "aiohttp.ClientSession.get",
            side_effect=lambda *args, **kwargs: AsyncMock(
                __aenter__=AsyncMock(
                    return_value=success_response if kwargs.get("url") == expected_url else not_found_response
                )
            ),
        )

    def mock_series_of_http_responses(self, responses: List[ClientResponse], mocker):
        responses_iter = iter(responses)

        return mocker.patch(
            "aiohttp.ClientSession.get",
            side_effect=lambda *args, **kwargs: AsyncMock(
                __aenter__=AsyncMock(return_value=next(responses_iter)), __aexit__=AsyncMock()
            ),
        )

    def mock_request_agnostic_http_response(self, mock_response: ClientResponse, mocker):
        return mocker.patch(
            "aiohttp.ClientSession.get",
            side_effect=lambda *args, **kwargs: AsyncMock(__aenter__=AsyncMock(return_value=mock_response)),
        )

    def patch_resolver_resolve_with_side_effect(self, mocker, side_effect):
        return mocker.patch("dns.asyncresolver.resolve", new_callable=AsyncMock, side_effect=side_effect)

    def patch_resolver_with_answer_or_exception(self, mocker, mocked_response_or_exception):
        # noinspection PyUnusedLocal
        async def side_effect(domain_name, rdtype):
            if isinstance(mocked_response_or_exception, Exception):
                raise mocked_response_or_exception
            return mocked_response_or_exception

        return self.patch_resolver_resolve_with_side_effect(mocker, side_effect)

    def mock_request_specific_dns_resolve_call(self, dcv_request: DcvCheckRequest, mocker) -> MagicMock:
        dns_name_prefix = dcv_request.dcv_check_parameters.validation_details.dns_name_prefix
        if dns_name_prefix is not None and len(dns_name_prefix) > 0:
            expected_domain = f"{dns_name_prefix}.{dcv_request.domain_or_ip_target}"
        else:
            expected_domain = dcv_request.domain_or_ip_target

        match dcv_request.dcv_check_parameters.validation_details.validation_method:
            case DcvValidationMethod.CONTACT_PHONE:
                if dcv_request.dcv_check_parameters.validation_details.dns_record_type == DnsRecordType.TXT:
                    expected_domain = f"_validation-contactphone.{dcv_request.domain_or_ip_target}"
                else:  # CAA -- using dns names instead of strings
                    expected_domain = dns.name.from_text(expected_domain)
            case DcvValidationMethod.CONTACT_EMAIL:
                if dcv_request.dcv_check_parameters.validation_details.dns_record_type == DnsRecordType.TXT:
                    expected_domain = f"_validation-contactemail.{dcv_request.domain_or_ip_target}"
                else:  # CAA -- using dns names instead of strings
                    expected_domain = dns.name.from_text(expected_domain)
        test_dns_query_answer = self.create_basic_dns_response_for_mock(dcv_request, mocker)

        # noinspection PyUnusedLocal
        async def side_effect(domain_name, rdtype):
            if domain_name == expected_domain:
                return test_dns_query_answer
            raise self.raise_(dns.resolver.NoAnswer)

        return self.patch_resolver_resolve_with_side_effect(mocker, side_effect)

    def mock_dns_resolve_call_with_specific_response_code(self, dcv_request: DcvCheckRequest, response_code, mocker):
        test_dns_query_answer = self.create_basic_dns_response_for_mock(dcv_request, mocker)
        test_dns_query_answer.response.rcode = lambda: response_code
        self.patch_resolver_with_answer_or_exception(mocker, test_dns_query_answer)

    def mock_dns_resolve_call_with_specific_flag(self, dcv_request: DcvCheckRequest, flag, mocker):
        test_dns_query_answer = self.create_basic_dns_response_for_mock(dcv_request, mocker)
        test_dns_query_answer.response.flags |= flag
        self.patch_resolver_with_answer_or_exception(mocker, test_dns_query_answer)

    def mock_dns_resolve_call_getting_multiple_txt_records(self, dcv_request: DcvCheckRequest, mocker):
        dcv_details = dcv_request.dcv_check_parameters.validation_details
        match dcv_request.dcv_check_parameters.validation_details.validation_method:
            case DcvValidationMethod.DNS_CHANGE:
                record_data = {"value": dcv_details.challenge_value}
                record_name_prefix = dcv_details.dns_name_prefix
            case _:
                record_data = {"value": dcv_details.key_authorization}
                record_name_prefix = "_acme-challenge"
        txt_record_1 = MockDnsObjectCreator.create_record_by_type(DnsRecordType.TXT, record_data)
        txt_record_2 = MockDnsObjectCreator.create_record_by_type(DnsRecordType.TXT, {"value": "whatever2"})
        txt_record_3 = MockDnsObjectCreator.create_record_by_type(DnsRecordType.TXT, {"value": "whatever3"})
        test_dns_query_answer = MockDnsObjectCreator.create_dns_query_answer_with_multiple_records(
            dcv_request.domain_or_ip_target,
            record_name_prefix,
            DnsRecordType.TXT,
            *[txt_record_1, txt_record_2, txt_record_3],
            mocker=mocker,
        )
        self.patch_resolver_with_answer_or_exception(mocker, test_dns_query_answer)

    def create_basic_dns_response_for_mock(self, dcv_request: DcvCheckRequest, mocker) -> dns.resolver.Answer:
        dcv_details = dcv_request.dcv_check_parameters.validation_details
        match dcv_details.validation_method:
            case DcvValidationMethod.DNS_CHANGE | DcvValidationMethod.IP_LOOKUP:
                match dcv_details.dns_record_type:
                    case DnsRecordType.CNAME | DnsRecordType.TXT | DnsRecordType.A | DnsRecordType.AAAA:
                        record_data = {"value": dcv_details.challenge_value}
                    case _:  # CAA
                        record_data = {"flags": "", "tag": "issue", "value": dcv_details.challenge_value}
            case DcvValidationMethod.CONTACT_EMAIL:
                if dcv_details.dns_record_type == DnsRecordType.CAA:
                    record_data = {"flags": "", "tag": "contactemail", "value": dcv_details.challenge_value}
                else:
                    record_data = {"value": dcv_details.challenge_value}
            case DcvValidationMethod.CONTACT_PHONE:
                if dcv_details.dns_record_type == DnsRecordType.CAA:
                    record_data = {"flags": "", "tag": "contactphone", "value": dcv_details.challenge_value}
                else:
                    record_data = {"value": dcv_details.challenge_value}
            case _:  # ACME_DNS_01
                record_data = {"value": dcv_details.key_authorization}
        record_type = dcv_details.dns_record_type
        record_prefix = dcv_details.dns_name_prefix
        test_dns_query_answer = MockDnsObjectCreator.create_dns_query_answer(
            dcv_request.domain_or_ip_target, record_prefix, record_type, record_data, mocker
        )
        return test_dns_query_answer

    def create_http_redirect_history(self):
        redirect_url_1 = f"https://example.com/redirected-1"
        redirect_response_1 = TestMpicDcvChecker.create_mock_http_redirect_response(301, redirect_url_1)
        redirect_url_2 = f"https://example.com/redirected-2"
        redirect_response_2 = TestMpicDcvChecker.create_mock_http_redirect_response(302, redirect_url_2)
        return [redirect_response_1, redirect_response_2]


if __name__ == "__main__":
    pytest.main()
