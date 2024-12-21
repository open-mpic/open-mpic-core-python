import pytest

from open_mpic_core.common_domain.check_parameters import DcvAcmeHttp01ValidationDetails, \
    DcvWebsiteChangeValidationDetails, DcvDnsChangeValidationDetails, DcvAcmeDns01ValidationDetails, \
    DcvContactPhoneTxtValidationDetails, DcvContactEmailCaaValidationDetails, DcvContactEmailTxtValidationDetails, \
    DcvContactPhoneCaaValidationDetails, DcvIpLookupValidationDetails, DcvValidationDetails


class TestCheckRequestDetails:
    @pytest.mark.parametrize('details_as_json, expected_class', [
        ('{"validation_method": "website-change-v2", "challenge_value": "test-cv", "http_token_path": "test-htp", "url_scheme": "https"}', DcvWebsiteChangeValidationDetails),
        ('{"validation_method": "dns-change", "dns_name_prefix": "test-dnp", "dns_record_type": "TXT", "challenge_value": "test-cv"}', DcvDnsChangeValidationDetails),
        ('{"validation_method": "dns-change", "dns_name_prefix": "test-dnp", "dns_record_type": "CAA", "challenge_value": "test-cv"}', DcvDnsChangeValidationDetails),
        ('{"validation_method": "acme-http-01", "token": "test-t", "key_authorization": "test-ka"}', DcvAcmeHttp01ValidationDetails),
        ('{"validation_method": "acme-dns-01", "key_authorization": "test-ka" }', DcvAcmeDns01ValidationDetails),
        ('{"validation_method": "contact-email", "dns_record_type": "TXT", "challenge_value": "test-cv"}', DcvContactEmailTxtValidationDetails),
        ('{"validation_method": "contact-email", "dns_name_prefix": "test-dnp", "dns_record_type": "CAA", "challenge_value": "test-cv"}', DcvContactEmailCaaValidationDetails),
        ('{"validation_method": "contact-phone", "dns_record_type": "TXT", "challenge_value": "test-cv"}', DcvContactPhoneTxtValidationDetails),
        ('{"validation_method": "contact-phone", "dns_name_prefix": "test-dnp", "dns_record_type": "CAA", "challenge_value": "test-cv"}', DcvContactPhoneCaaValidationDetails),
        ('{"validation_method": "ip-lookup", "dns_name_prefix": "test-dnp", "dns_record_type": "A", "challenge_value": "test-cv"}', DcvIpLookupValidationDetails)
    ])
    def check_request_details__should_automatically_deserialize_into_correct_object_based_on_discriminator(self, details_as_json, expected_class):
        details_as_object: DcvValidationDetails = expected_class.model_validate_json(details_as_json)
        assert isinstance(details_as_object, expected_class)


if __name__ == '__main__':
    pytest.main()
