import json
import pydantic
import pytest
from open_mpic_core import CheckType
from open_mpic_core import MpicCaaRequest

from unit.test_util.valid_mpic_request_creator import ValidMpicRequestCreator


# noinspection PyMethodMayBeStatic
class TestMpicCaaRequest:
    """
    Tests correctness of configuration for Pydantic-driven auto validation of MpicCaaRequest objects.
    """

    def model_validate_json__should_return_caa_mpic_request_given_valid_caa_json(self):
        request = ValidMpicRequestCreator.create_valid_caa_mpic_request()
        mpic_request = MpicCaaRequest.model_validate_json(json.dumps(request.model_dump()))
        assert mpic_request.domain_or_ip_target == request.domain_or_ip_target

    def mpic_caa_request__should_require_domain_or_ip_target(self):
        request = ValidMpicRequestCreator.create_valid_caa_mpic_request()
        # noinspection PyTypeChecker
        request.domain_or_ip_target = None
        with pytest.raises(pydantic.ValidationError) as validation_error:
            MpicCaaRequest.model_validate_json(json.dumps(request.model_dump()))
        assert "domain_or_ip_target" in str(validation_error.value)

    @pytest.mark.parametrize("certificate_type", ["invalid"])
    def mpic_caa_request__should_require_valid_certificate_type(self, certificate_type):
        request = ValidMpicRequestCreator.create_valid_caa_mpic_request()
        request.caa_check_parameters.certificate_type = certificate_type
        with pytest.raises(pydantic.ValidationError) as validation_error:
            MpicCaaRequest.model_validate_json(json.dumps(request.model_dump(warnings=False)))
        assert "certificate_type" in str(validation_error.value)
        assert "tls-server" in str(validation_error.value)  # should say input should be 'tls-server' or 's-mime'

    def mpic_caa_request__should_have_check_type_set_to_caa(self):
        request = ValidMpicRequestCreator.create_valid_caa_mpic_request()
        mpic_request = MpicCaaRequest.model_validate_json(json.dumps(request.model_dump()))
        assert mpic_request.check_type == CheckType.CAA


if __name__ == "__main__":
    pytest.main()
