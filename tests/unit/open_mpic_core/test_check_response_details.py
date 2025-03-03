import pytest

from open_mpic_core import DcvDnsCheckResponseDetails, DcvHttpCheckResponseDetails


class TestCheckResponseDetails:
    # fmt: off
    @pytest.mark.parametrize('details_as_json, expected_class', [
        ('{"validation_method": "dns-change", "records_seen": ["foo"], "response_code": 5, "ad_flag": true, "found_at": "example.com"}',
         DcvDnsCheckResponseDetails),
        ('{"validation_method": "acme-dns-01", "records_seen": ["foo"], "response_code": 5, "ad_flag": true, "found_at": "example.com"}',
         DcvDnsCheckResponseDetails),
        ('{"validation_method": "contact-email-txt", "records_seen": ["foo"], "response_code": 5, "ad_flag": true, "found_at": "example.com"}',
         DcvDnsCheckResponseDetails),
        ('{"validation_method": "contact-email-caa", "records_seen": ["foo"], "response_code": 5, "ad_flag": true, "found_at": "example.com"}',
         DcvDnsCheckResponseDetails),
        ('{"validation_method": "contact-phone-txt", "records_seen": ["foo"], "response_code": 5, "ad_flag": true, "found_at": "example.com"}',
         DcvDnsCheckResponseDetails),
        ('{"validation_method": "contact-phone-caa", "records_seen": ["foo"], "response_code": 5, "ad_flag": true, "found_at": "example.com"}',
         DcvDnsCheckResponseDetails),
        ('{"validation_method": "ip-address", "records_seen": ["foo"], "response_code": 5, "ad_flag": true, "found_at": "example.com"}',
         DcvDnsCheckResponseDetails),
        ('{"validation_method": "website-change", "response_history": [], "response_url": "example.com", "response_status_code": 200, "response_page": "foo"}',
         DcvHttpCheckResponseDetails),
        ('{"validation_method": "acme-http-01", "response_history": [], "response_url": "example.com", "response_status_code": 200, "response_page": "foo"}',
         DcvHttpCheckResponseDetails),
    ])
    # fmt: on
    def check_response_details__should_automatically_deserialize_into_correct_object_based_on_discriminator(self, details_as_json, expected_class):
        details_as_object = expected_class.model_validate_json(details_as_json)
        assert isinstance(details_as_object, expected_class)


if __name__ == '__main__':
    pytest.main()
