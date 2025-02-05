import pytest
from pydantic import TypeAdapter

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
        ('{"validation_method": "dns-change", "dns_name_prefix": "test-dnp", "dns_record_type": "CAA", "challenge_value": "test-cv"}',
         DcvDnsChangeValidationParameters),
        ('{"validation_method": "acme-http-01", "token": "test-t", "key_authorization": "test-ka"}',
         DcvAcmeHttp01ValidationParameters),
        ('{"validation_method": "acme-dns-01", "key_authorization": "test-ka"}',
         DcvAcmeDns01ValidationParameters),
        ('{"validation_method": "contact-email", "dns_record_type": "TXT", "challenge_value": "test-cv"}',
         DcvContactEmailTxtValidationParameters),
        ('{"validation_method": "contact-email", "dns_name_prefix": "test-dnp", "dns_record_type": "CAA", "challenge_value": "test-cv"}',
         DcvContactEmailCaaValidationParameters),
        ('{"validation_method": "contact-phone", "dns_record_type": "TXT", "challenge_value": "test-cv"}',
         DcvContactPhoneTxtValidationParameters),
        ('{"validation_method": "contact-phone", "dns_name_prefix": "test-dnp", "dns_record_type": "CAA", "challenge_value": "test-cv"}',
         DcvContactPhoneCaaValidationParameters),
        ('{"validation_method": "ip-address", "dns_name_prefix": "test-dnp", "dns_record_type": "A", "challenge_value": "test-cv"}',
         DcvIpAddressValidationParameters),
        ('{"validation_method": "contact-email", "challenge_value": "abc"}',  # it defaults to TXT... wonder why...
         DcvContactEmailTxtValidationParameters)
    ])
    # fmt: on
    def check_request_parameters__should_automatically_deserialize_into_correct_object_based_on_discriminator(
        self, parameters_as_json, expected_class
    ):
        type_adapter = TypeAdapter(DcvCheckParameters)  # have it automatically figure it out
        details_as_object: DcvCheckParameters = type_adapter.validate_json(parameters_as_json)
        assert isinstance(details_as_object, expected_class)


if __name__ == "__main__":
    pytest.main()
