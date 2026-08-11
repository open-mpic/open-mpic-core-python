import json
import pydantic
import pytest
from pydantic import TypeAdapter

from open_mpic_core import CheckType
from open_mpic_core import MpicRequest

from unit.test_util.valid_mpic_request_creator import ValidMpicRequestCreator


# noinspection PyMethodMayBeStatic
class TestMpicRequest:
    """
    Tests correctness of configuration for Pydantic-driven auto validation of MpicRequest objects.
    """

    @pytest.mark.parametrize("check_type", [CheckType.CAA, CheckType.DCV])
    def mpic_request__should_be_deserialized_into_the_request_type_named_by_check_type(self, check_type):
        request = ValidMpicRequestCreator.create_valid_mpic_request(check_type)
        type_adapter = TypeAdapter(MpicRequest)
        mpic_request = type_adapter.validate_json(json.dumps(request.model_dump(warnings=False)))
        assert mpic_request.check_type == check_type

    def mpic_request__should_require_check_type(self):
        request = ValidMpicRequestCreator.create_valid_dcv_mpic_request()
        request_body = request.model_dump(warnings=False)
        del request_body["check_type"]  # check_type is required by the API specification
        type_adapter = TypeAdapter(MpicRequest)
        with pytest.raises(pydantic.ValidationError) as validation_error:
            type_adapter.validate_json(json.dumps(request_body))
        assert validation_error.value.errors()[0]["type"] == "union_tag_not_found"

    def mpic_request__should_report_only_the_issues_of_the_request_type_named_by_check_type(self):
        request = ValidMpicRequestCreator.create_valid_dcv_mpic_request()
        # noinspection PyTypeChecker
        request.domain_or_ip_target = None
        type_adapter = TypeAdapter(MpicRequest)
        with pytest.raises(pydantic.ValidationError) as validation_error:
            type_adapter.validate_json(json.dumps(request.model_dump(warnings=False)))
        issues = validation_error.value.errors()
        assert len(issues) == 1  # without the discriminator every request type would report its own issues
        assert issues[0]["loc"] == (CheckType.DCV, "domain_or_ip_target")


if __name__ == "__main__":
    pytest.main()
