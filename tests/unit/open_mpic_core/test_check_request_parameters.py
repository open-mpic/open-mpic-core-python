import pytest
from pydantic import TypeAdapter

from open_mpic_core import (
    DcvAcmeHttp01ValidationParameters,
    DcvWebsiteChangeValidationParameters,
    DcvDnsChangeValidationParameters,
    DcvDnsPersistentValidationParameters,
    DcvAcmeDns01ValidationParameters,
    DcvContactPhoneTxtValidationParameters,
    DcvContactEmailCaaValidationParameters,
    DcvContactEmailTxtValidationParameters,
    DcvContactPhoneCaaValidationParameters,
    DcvIpAddressValidationParameters,
    DcvCheckParameters,
    DnsRecordType
)


class TestCheckRequestDetails:
    # fmt: off
    @pytest.mark.parametrize("parameters_as_json, expected_class", [
        ('{"validation_method": "website-change", "challenge_value": "test-cv", "http_token_path": "test-htp", "url_scheme": "https"}',
         DcvWebsiteChangeValidationParameters),
        ('{"validation_method": "dns-change", "dns_name_prefix": "test-dnp", "dns_record_type": "TXT", "challenge_value": "test-cv"}',
         DcvDnsChangeValidationParameters),
        ('{"validation_method": "dns-change", "dns_record_type": "CNAME", "challenge_value": "test-cv"}',
         DcvDnsChangeValidationParameters),
        ('{"validation_method": "dns-persistent", "issuer_domain_names": ["authority.example"], "expected_account_uri": "https://authority.example/acct/123"}',
         DcvDnsPersistentValidationParameters),
        ('{"validation_method": "acme-http-01", "token": "test-t", "key_authorization": "test-ka"}',
         DcvAcmeHttp01ValidationParameters),
        ('{"validation_method": "acme-dns-01", "key_authorization_hash": "test-ka"}',
         DcvAcmeDns01ValidationParameters),
        ('{"validation_method": "contact-email-txt", "challenge_value": "test-cv"}',
         DcvContactEmailTxtValidationParameters),
        ('{"validation_method": "contact-email-caa", "challenge_value": "test-cv"}',
         DcvContactEmailCaaValidationParameters),
        ('{"validation_method": "contact-phone-txt", "challenge_value": "test-cv"}',
         DcvContactPhoneTxtValidationParameters),
        ('{"validation_method": "contact-phone-caa", "dns_name_prefix": "test-dnp", "challenge_value": "test-cv"}',
         DcvContactPhoneCaaValidationParameters),
        ('{"validation_method": "ip-address", "dns_name_prefix": "test-dnp", "dns_record_type": "A", "challenge_value": "test-cv"}',
         DcvIpAddressValidationParameters),
    ])
    # fmt: on
    def check_request_parameters__should_automatically_deserialize_into_correct_object_based_on_discriminator(
        self, parameters_as_json, expected_class
    ):
        type_adapter = TypeAdapter(DcvCheckParameters)  # have it automatically figure it out
        details_as_object: DcvCheckParameters = type_adapter.validate_json(parameters_as_json)
        assert isinstance(details_as_object, expected_class)

    # fmt: off
    @pytest.mark.parametrize("parameters_as_json, test_description", [
        ('{"validation_method": "dns-change", "dns_record_type": "AAAA", "challenge_value": "test-cv"}',
         "should fail validation when DNS record type is invalid like AAAA for DNS Change"),
        ('{"validation_method": "contact-email", "challenge_value": "test-cv"}',
         "should fail validation when DNS record type is missing for Contact Email"),
        ('{"validation_method": "contact-phone", "dns_record_type": "CNAME", "challenge_value": "test-cv"}',
         "should fail validation when DNS record type is invalid for Contact Phone"),
        ('{"validation_method": "ip-address", "dns_record_type": "TXT", "challenge_value": "test-cv"}',
         "should fail validation when DNS record type is invalid like TXT for IP Address"),
        ('{"validation_method": "dns-persistent", "expected_account_uri": "https://authority.example/acct/123"}',
         "should fail validation when required issuer_domain_names is missing for DNS Persistent"),
        ('{"validation_method": "dns-persistent", "issuer_domain_names": ["authority.example"]}',
         "should fail validation when required expected_account_uri is missing for DNS Persistent"),
        ('{"validation_method": "dns-persistent", "issuer_domain_names": ["authority.example"], "expected_account_uri": "not-a-valid-uri"}',
         "should fail validation when expected_account_uri is not a valid URI for DNS Persistent"),
        ('{"validation_method": "dns-persistent", "issuer_domain_names": [""], "expected_account_uri": "https://authority.example/acct/123"}',
         "should fail validation when issuer_domain_names contains an empty string for DNS Persistent"),
    ])
    # fmt: on
    def check_request_parameters__should_fail_validation_when_serialized_object_is_malformed(
        self, parameters_as_json, test_description
    ):
        type_adapter = TypeAdapter(DcvCheckParameters)
        with pytest.raises(Exception) as validation_error:
            type_adapter.validate_json(parameters_as_json)
        assert isinstance(validation_error.value, ValueError)

    # fmt: off
    @pytest.mark.parametrize("account_uri", [
        "http://authority.example/acct/123",
        "mailto:123@example.com",
        "acct:abc123@example.com"
    ])
    # fmt: on
    def check_request_parameters__should_accept_valid_uri_format_for_expected_account_uri_in_dns_persistent_validation(
        self, account_uri
    ):
        parameters_as_json = f'{{"validation_method": "dns-persistent", "issuer_domain_names": ["authority.example"], "expected_account_uri": "{account_uri}"}}'
        type_adapter = TypeAdapter(DcvCheckParameters)
        details_as_object: DcvCheckParameters = type_adapter.validate_json(parameters_as_json)
        assert isinstance(details_as_object, DcvDnsPersistentValidationParameters)
        assert details_as_object.expected_account_uri == account_uri

    # fmt: off
    @pytest.mark.parametrize("record_type, is_always_case_insensitive", [
        (DnsRecordType.CNAME, True), (DnsRecordType.TXT, False), (DnsRecordType.CAA, True)
    ])
    # fmt: on
    def check_request_parameters__should_force_case_sensitivity_to_false_for_non_txt_dns_records(
        self, record_type, is_always_case_insensitive
    ):
        # notice require_exact_case is true in the serialized JSON; it should be forced to False for non-TXT records
        parameters_as_json = f'{{"validation_method": "dns-change", "dns_record_type": "{record_type}", "challenge_value": "test-cv", "require_exact_case": true}}'
        type_adapter = TypeAdapter(DcvCheckParameters)
        details_as_object: DcvCheckParameters = type_adapter.validate_json(parameters_as_json)
        assert isinstance(details_as_object, DcvDnsChangeValidationParameters)
        if is_always_case_insensitive:
            assert details_as_object.require_exact_case is False  # should be forced to False for non-TXT records
        else:
            assert details_as_object.require_exact_case is True

    @staticmethod
    def check_request_parameters__should_disallow_setting_case_sensitivity_to_false_for_acme_dns_01():
        parameters_as_json = '{"validation_method": "acme-dns-01", "key_authorization_hash": "test-kah", "require_exact_case": false}'
        type_adapter = TypeAdapter(DcvCheckParameters)
        with pytest.raises(Exception) as validation_error:
            type_adapter.validate_json(parameters_as_json)
        assert isinstance(validation_error.value, ValueError)

    @staticmethod
    def check_request_parameters__should_disallow_setting_case_sensitivity_to_false_for_acme_http_01():
        parameters_as_json = '{"validation_method": "acme-http-01", "token:" "test", "key_authorization": "test-ka", "require_exact_case": false}'
        type_adapter = TypeAdapter(DcvCheckParameters)
        with pytest.raises(Exception) as validation_error:
            type_adapter.validate_json(parameters_as_json)
        assert isinstance(validation_error.value, ValueError)


if __name__ == "__main__":
    pytest.main()
