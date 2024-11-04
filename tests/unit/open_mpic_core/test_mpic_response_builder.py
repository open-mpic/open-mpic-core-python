import pytest
from open_mpic_core.common_domain.check_response import CaaCheckResponse, DcvCheckResponse, CaaCheckResponseDetails, DcvCheckResponseDetails
from open_mpic_core.common_domain.enum.check_type import CheckType
from open_mpic_core.mpic_coordinator.mpic_response_builder import MpicResponseBuilder

from unit.test_util.valid_mpic_request_creator import ValidMpicRequestCreator


class TestMpicResponseBuilder:
    @staticmethod
    def create_perspective_responses_per_check_type(check_type=CheckType.DCV):
        responses = {}
        caa_responses = [  # 1 false
            CaaCheckResponse(perspective='p1', check_passed=True, details=CaaCheckResponseDetails(caa_record_present=False)),
            CaaCheckResponse(perspective='p2', check_passed=False, details=CaaCheckResponseDetails(caa_record_present=False)),
            CaaCheckResponse(perspective='p3', check_passed=True, details=CaaCheckResponseDetails(caa_record_present=False)),
            CaaCheckResponse(perspective='p4', check_passed=True, details=CaaCheckResponseDetails(caa_record_present=False)),
            CaaCheckResponse(perspective='p5', check_passed=True, details=CaaCheckResponseDetails(caa_record_present=False)),
            CaaCheckResponse(perspective='p6', check_passed=True, details=CaaCheckResponseDetails(caa_record_present=False))
        ]
        dcv_responses = [  # 2 false
            DcvCheckResponse(perspective='p1', check_passed=True, details=DcvCheckResponseDetails()),
            DcvCheckResponse(perspective='p2', check_passed=True, details=DcvCheckResponseDetails()),
            DcvCheckResponse(perspective='p3', check_passed=True, details=DcvCheckResponseDetails()),
            DcvCheckResponse(perspective='p4', check_passed=True, details=DcvCheckResponseDetails()),
            DcvCheckResponse(perspective='p5', check_passed=False, details=DcvCheckResponseDetails()),
            DcvCheckResponse(perspective='p6', check_passed=False, details=DcvCheckResponseDetails())
        ]

        match check_type:
            case CheckType.CAA:
                responses[CheckType.CAA] = caa_responses
            case CheckType.DCV:
                responses[CheckType.DCV] = dcv_responses

        return responses

    @staticmethod
    def create_validity_by_check_type(check_type=CheckType.CAA):
        validity_by_check_type = {}
        match check_type:
            case CheckType.CAA:
                validity_by_check_type[CheckType.CAA] = True
            case CheckType.DCV:
                validity_by_check_type[CheckType.DCV] = False
        return validity_by_check_type

    @pytest.mark.parametrize('check_type, perspective_count, quorum_count', [
        (CheckType.CAA, 6, 4),
        (CheckType.DCV, 6, 5),  # higher quorum count
    ])
    def build_response__should_return_response_given_mpic_request_configuration_and_results(self, check_type, perspective_count, quorum_count):
        persp_responses_per_check_type = self.create_perspective_responses_per_check_type(check_type)
        valid_by_check_type = self.create_validity_by_check_type(check_type)
        request = ValidMpicRequestCreator.create_valid_mpic_request(check_type)
        mpic_response = MpicResponseBuilder.build_response(request, perspective_count, quorum_count, 2,
                                                           persp_responses_per_check_type, valid_by_check_type)
        assert (mpic_response.request_orchestration_parameters.perspective_count ==
                request.orchestration_parameters.perspective_count)
        assert mpic_response.actual_orchestration_parameters.perspective_count == perspective_count
        assert mpic_response.actual_orchestration_parameters.quorum_count == quorum_count
        assert mpic_response.actual_orchestration_parameters.attempt_count == 2

        match check_type:
            case CheckType.CAA:
                # response_body = MpicCaaResponse.model_validate(json.loads(response['body']))
                assert mpic_response.perspectives == persp_responses_per_check_type[CheckType.CAA]
                assert mpic_response.is_valid == valid_by_check_type[CheckType.CAA]
            case CheckType.DCV:
                assert mpic_response.perspectives == persp_responses_per_check_type[CheckType.DCV]
                assert mpic_response.is_valid == valid_by_check_type[CheckType.DCV]

    def build_response__should_include_validation_details_and_method_when_present_in_request_body(self):
        request = ValidMpicRequestCreator.create_valid_dcv_mpic_request()
        persp_responses_per_check_type = self.create_perspective_responses_per_check_type(CheckType.DCV)
        valid_by_check_type = self.create_validity_by_check_type(CheckType.DCV)
        mpic_response = MpicResponseBuilder.build_response(request, 6, 5, 1,
                                                           persp_responses_per_check_type, valid_by_check_type)
        assert mpic_response.dcv_check_parameters.validation_details.challenge_value == request.dcv_check_parameters.validation_details.challenge_value
        assert mpic_response.dcv_check_parameters.validation_details.validation_method == request.dcv_check_parameters.validation_details.validation_method


if __name__ == '__main__':
    pytest.main()
