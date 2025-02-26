import pytest
from pydantic import TypeAdapter, ValidationError

from open_mpic_core import (
    DcvAcmeHttp01ValidationParameters,
    DcvWebsiteChangeValidationParameters,
    DcvDnsChangeValidationParameters,
    DcvAcmeDns01ValidationParameters,
    DcvContactPhoneTxtValidationParameters,
    DcvContactEmailCaaValidationParameters,
    DcvContactEmailTxtValidationParameters,
    DcvContactPhoneCaaValidationParameters,
    DcvIpAddressValidationParameters,
    DcvCheckParameters,
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
    ])
    # fmt: on
    def check_request_parameters__should_fail_validation_when_serialized_object_is_malformed(
        self, parameters_as_json, test_description
    ):
        type_adapter = TypeAdapter(DcvCheckParameters)
        with pytest.raises(Exception) as validation_error:
            type_adapter.validate_json(parameters_as_json)
        assert isinstance(validation_error.value, ValueError)


if __name__ == "__main__":
    pytest.main()
