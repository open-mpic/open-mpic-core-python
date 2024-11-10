import json
import pydantic
import pytest
from setuptools.package_index import URL_SCHEME

from open_mpic_core.common_domain.check_parameters import DcvWebsiteChangeValidationDetails
from open_mpic_core.common_domain.enum.check_type import CheckType
from open_mpic_core.common_domain.enum.dcv_validation_method import DcvValidationMethod
from open_mpic_core.common_domain.enum.url_scheme import UrlScheme
from open_mpic_core.mpic_coordinator.domain.mpic_request import MpicDcvRequest

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

    # TODO this is probably not a valid test given that perspectives are for diagnostics mode only
    # it likely needs different logic overall
    def model_validate_json__should_throw_validation_error_given_both_perspectives_and_perspective_count_present(self):
        request = ValidMpicRequestCreator.create_valid_dcv_mpic_request()
        request.orchestration_parameters.perspective_count = 1
        request.orchestration_parameters.perspectives = ['test']
        with pytest.raises(pydantic.ValidationError) as validation_error:
            MpicDcvRequest.model_validate_json(json.dumps(request.model_dump()))
        assert 'perspective_count' in str(validation_error.value)
        assert 'perspectives' in str(validation_error.value)

    def model_validate_json__should_throw_validation_error_given_missing_dcv_check_parameters(self):
        request = ValidMpicRequestCreator.create_valid_dcv_mpic_request()
        request.dcv_check_parameters = None
        with pytest.raises(pydantic.ValidationError) as validation_error:
            MpicDcvRequest.model_validate_json(json.dumps(request.model_dump()))
        assert 'dcv_check_parameters' in str(validation_error.value)

    def model_validate_json__should_throw_validation_error_given_missing_validation_method_in_validation_details(self):
        request = ValidMpicRequestCreator.create_valid_dcv_mpic_request()
        request.dcv_check_parameters.validation_details.validation_method = None
        with pytest.raises(pydantic.ValidationError) as validation_error:
            MpicDcvRequest.model_validate_json(json.dumps(request.model_dump()))
        assert 'validation_method' in str(validation_error.value)

    def model_validate_json__should_throw_validation_error_given_invalid_validation_method_in_validation_details(self):
        request = ValidMpicRequestCreator.create_valid_dcv_mpic_request()
        request.dcv_check_parameters.validation_details.validation_method = 'invalid'
        with pytest.raises(pydantic.ValidationError) as validation_error:
            MpicDcvRequest.model_validate_json(json.dumps(request.model_dump(warnings=False)))
        assert 'validation_method' in str(validation_error.value)
        assert 'invalid' in str(validation_error.value)

    def model_validate_json__should_throw_validation_error_given_missing_validation_details(self):
        request = ValidMpicRequestCreator.create_valid_dcv_mpic_request()
        request.dcv_check_parameters.validation_details = None
        with pytest.raises(pydantic.ValidationError) as validation_error:
            MpicDcvRequest.model_validate_json(json.dumps(request.model_dump()))
        assert 'validation_details' in str(validation_error.value)

    def model_validate_json__should_throw_validation_error_given_missing_challenge_value(self):
        request = ValidMpicRequestCreator.create_valid_dcv_mpic_request()
        request.dcv_check_parameters.validation_details.challenge_value = None
        with pytest.raises(pydantic.ValidationError) as validation_error:
            MpicDcvRequest.model_validate_json(json.dumps(request.model_dump()))
        assert 'challenge_value' in str(validation_error.value)

    def model_validate_json__should_throw_validation_error_given_missing_prefix_for_dns_validation(self):
        request = ValidMpicRequestCreator.create_valid_dcv_mpic_request(DcvValidationMethod.DNS_CHANGE)
        request.dcv_check_parameters.validation_details.dns_name_prefix = None
        with pytest.raises(pydantic.ValidationError) as validation_error:
            MpicDcvRequest.model_validate_json(json.dumps(request.model_dump()))
        assert 'dns_name_prefix' in str(validation_error.value)

    def model_validate_json__should_throw_validation_error_given_missing_record_type_for_dns_validation(self):
        request = ValidMpicRequestCreator.create_valid_dcv_mpic_request(DcvValidationMethod.DNS_CHANGE)
        request.dcv_check_parameters.validation_details.dns_record_type = None
        with pytest.raises(pydantic.ValidationError) as validation_error:
            MpicDcvRequest.model_validate_json(json.dumps(request.model_dump()))
        assert 'dns_record_type' in str(validation_error.value)

    def model_validate_json__should_throw_validation_error_given_invalid_record_type_for_dns_validation(self):
        request = ValidMpicRequestCreator.create_valid_dcv_mpic_request(DcvValidationMethod.DNS_CHANGE)
        request.dcv_check_parameters.validation_details.dns_record_type = 'invalid'
        with pytest.raises(pydantic.ValidationError) as validation_error:
            MpicDcvRequest.model_validate_json(json.dumps(request.model_dump(warnings=False)))
        assert 'dns_record_type' in str(validation_error.value)
        assert 'invalid' in str(validation_error.value)

    def model_validate_json__should_throw_validation_error_given_missing_token_path_for_http_validation(self):
        request = ValidMpicRequestCreator.create_valid_dcv_mpic_request(DcvValidationMethod.WEBSITE_CHANGE_V2)
        request.dcv_check_parameters.validation_details.http_token_path = None
        with pytest.raises(pydantic.ValidationError) as validation_error:
            MpicDcvRequest.model_validate_json(json.dumps(request.model_dump()))
        assert 'http_token_path' in str(validation_error.value)

    def mpic_dcv_request__should_have_check_type_set_to_dcv(self):
        request = ValidMpicRequestCreator.create_valid_dcv_mpic_request()
        mpic_request = MpicDcvRequest.model_validate_json(json.dumps(request.model_dump()))
        assert mpic_request.check_type == CheckType.DCV

    def mpic_dcv_request__should_default_to_http_scheme_for_website_change_validation_given_no_scheme_specified(self):
        request = ValidMpicRequestCreator.create_valid_dcv_mpic_request(DcvValidationMethod.WEBSITE_CHANGE_V2)
        request.dcv_check_parameters.validation_details = DcvWebsiteChangeValidationDetails(
            validation_method=DcvValidationMethod.WEBSITE_CHANGE_V2,
            challenge_value='test',
            http_token_path='example-path'
        )
        mpic_request = MpicDcvRequest.model_validate_json(json.dumps(request.model_dump()))
        assert mpic_request.dcv_check_parameters.validation_details.url_scheme == UrlScheme.HTTP


if __name__ == '__main__':
    pytest.main()
