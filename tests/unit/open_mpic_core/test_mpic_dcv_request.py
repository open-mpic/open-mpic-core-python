import json
import pydantic
import pytest

from open_mpic_core import DcvWebsiteChangeValidationParameters, CheckType,  DcvValidationMethod, UrlScheme, MpicDcvRequest

from unit.test_util.valid_mpic_request_creator import ValidMpicRequestCreator


# noinspection PyMethodMayBeStatic
class TestMpicDcvRequest:
    """
    Tests correctness of configuration for Pydantic-driven auto validation of MpicDcvRequest objects.
    """

    def model_validate_json__should_return_dcv_mpic_request_given_valid_dcv_json(self):
        request = ValidMpicRequestCreator.create_valid_dcv_mpic_request()
        mpic_request = MpicDcvRequest.model_validate_json(json.dumps(request.model_dump()))
        assert mpic_request.domain_or_ip_target == request.domain_or_ip_target

    def mpic_dcv_request__should_require_dcv_check_parameters(self):
        request = ValidMpicRequestCreator.create_valid_dcv_mpic_request()
        # noinspection PyTypeChecker
        request.dcv_check_parameters = None
        with pytest.raises(pydantic.ValidationError) as validation_error:
            MpicDcvRequest.model_validate_json(json.dumps(request.model_dump()))
        assert "dcv_check_parameters" in str(validation_error.value)

    def mpic_dcv_request__should_require_validation_method_in_check_parameters(self):
        request = ValidMpicRequestCreator.create_valid_dcv_mpic_request()
        request.dcv_check_parameters.validation_method = None
        with pytest.raises(pydantic.ValidationError) as validation_error:
            MpicDcvRequest.model_validate_json(json.dumps(request.model_dump()))
        assert "validation_method" in str(validation_error.value)

    def mpic_dcv_request__should_require_valid_validation_method_in_check_parameters(self):
        request = ValidMpicRequestCreator.create_valid_dcv_mpic_request()
        request.dcv_check_parameters.validation_method = "invalid"
        with pytest.raises(pydantic.ValidationError) as validation_error:
            MpicDcvRequest.model_validate_json(json.dumps(request.model_dump(warnings=False)))
        assert "validation_method" in str(validation_error.value)

    def mpic_dcv_request__should_require_challenge_value_in_check_parameters(self):
        request = ValidMpicRequestCreator.create_valid_dcv_mpic_request()
        # noinspection PyTypeChecker
        request.dcv_check_parameters.challenge_value = None
        with pytest.raises(pydantic.ValidationError) as validation_error:
            MpicDcvRequest.model_validate_json(json.dumps(request.model_dump()))
        assert "challenge_value" in str(validation_error.value)

    def mpic_dcv_request__should_require_dns_record_type_for_dns_change_validation(self):
        request = ValidMpicRequestCreator.create_valid_dcv_mpic_request(DcvValidationMethod.DNS_CHANGE)
        # noinspection PyTypeChecker
        request.dcv_check_parameters.dns_record_type = None
        with pytest.raises(pydantic.ValidationError) as validation_error:
            MpicDcvRequest.model_validate_json(json.dumps(request.model_dump()))
        assert "dns_record_type" in str(validation_error.value)

    def mpic_dcv_request__should_require_valid_dns_record_type_for_dns_change_validation(self):
        request = ValidMpicRequestCreator.create_valid_dcv_mpic_request(DcvValidationMethod.DNS_CHANGE)
        # noinspection PyTypeChecker
        request.dcv_check_parameters.dns_record_type = "invalid"
        with pytest.raises(pydantic.ValidationError) as validation_error:
            MpicDcvRequest.model_validate_json(json.dumps(request.model_dump(warnings=False)))
        assert "dns_record_type" in str(validation_error.value)
        assert "invalid" in str(validation_error.value)

    def mpic_dcv_request__should_require_http_token_path_for_website_change_validation(self):
        request = ValidMpicRequestCreator.create_valid_dcv_mpic_request(DcvValidationMethod.WEBSITE_CHANGE)
        # noinspection PyTypeChecker
        request.dcv_check_parameters.http_token_path = None
        with pytest.raises(pydantic.ValidationError) as validation_error:
            MpicDcvRequest.model_validate_json(json.dumps(request.model_dump()))
        assert "http_token_path" in str(validation_error.value)

    def mpic_dcv_request__should_require_token_for_acme_http_01_validation(self):
        request = ValidMpicRequestCreator.create_valid_dcv_mpic_request(DcvValidationMethod.ACME_HTTP_01)
        # noinspection PyTypeChecker
        request.dcv_check_parameters.token = None
        with pytest.raises(pydantic.ValidationError) as validation_error:
            MpicDcvRequest.model_validate_json(json.dumps(request.model_dump()))
        assert "token" in str(validation_error.value)

    @pytest.mark.parametrize("validation_method", [DcvValidationMethod.ACME_HTTP_01, DcvValidationMethod.ACME_DNS_01])
    def mpic_dcv_request__should_require_key_authorization_for_acme_validations(self, validation_method):
        request = ValidMpicRequestCreator.create_valid_dcv_mpic_request(validation_method)
        # noinspection PyTypeChecker
        if validation_method == DcvValidationMethod.ACME_HTTP_01:
            request.dcv_check_parameters.key_authorization = None
        else:
            request.dcv_check_parameters.key_authorization_hash = None
        with pytest.raises(pydantic.ValidationError) as validation_error:
            MpicDcvRequest.model_validate_json(json.dumps(request.model_dump()))
        assert "key_authorization" in str(validation_error.value)

    def mpic_dcv_request__should_have_check_type_set_to_dcv(self):
        request = ValidMpicRequestCreator.create_valid_dcv_mpic_request()
        mpic_request = MpicDcvRequest.model_validate_json(json.dumps(request.model_dump()))
        assert mpic_request.check_type == CheckType.DCV

    def mpic_dcv_request__should_default_to_http_scheme_for_website_change_validation_given_no_scheme_specified(self):
        request = ValidMpicRequestCreator.create_valid_dcv_mpic_request(DcvValidationMethod.WEBSITE_CHANGE)
        request.dcv_check_parameters = DcvWebsiteChangeValidationParameters(
            validation_method=DcvValidationMethod.WEBSITE_CHANGE,
            challenge_value="test",
            http_token_path="example-path",
        )
        mpic_request = MpicDcvRequest.model_validate_json(json.dumps(request.model_dump()))
        assert mpic_request.dcv_check_parameters.url_scheme == UrlScheme.HTTP

    @pytest.mark.parametrize(
        "validation_method, expected_prefix",
        [
            (DcvValidationMethod.CONTACT_EMAIL_TXT, "_validation-contactemail"),
            (DcvValidationMethod.CONTACT_PHONE_TXT, "_validation-contactphone"),
        ],
    )  # imperfect test because Pydantic seems to spit out a ton of errors trying to deserialize the JSON correctly
    def mpic_dcv_request__should_enforce_domain_prefix_for_contact_lookup_for_txt_records(
        self, validation_method, expected_prefix
    ):
        request = ValidMpicRequestCreator.create_valid_dcv_mpic_request(validation_method)
        request.dcv_check_parameters.dns_name_prefix = "moo"
        with pytest.raises(pydantic.ValidationError) as validation_error:
            MpicDcvRequest.model_validate_json(json.dumps(request.model_dump()))
        assert expected_prefix in str(validation_error.value)


if __name__ == "__main__":
    pytest.main()
