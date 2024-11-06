import pytest
from open_mpic_core.common_domain.check_response import CaaCheckResponse, DcvCheckResponse, CaaCheckResponseDetails, DcvCheckResponseDetails
from open_mpic_core.common_domain.check_response_details import DcvDnsChangeResponseDetails
from open_mpic_core.common_domain.enum.check_type import CheckType
from open_mpic_core.mpic_coordinator.mpic_response_builder import MpicResponseBuilder

from unit.test_util.valid_mpic_request_creator import ValidMpicRequestCreator


class TestMpicResponseBuilder:
    @staticmethod
    def create_perspective_responses_given_check_type(check_type=CheckType.DCV):
        responses = {}
        match check_type:
            case check_type.CAA:
                responses = [  # 1 false
                    CaaCheckResponse(perspective_code='p1', check_passed=True, details=CaaCheckResponseDetails(caa_record_present=False)),
                    CaaCheckResponse(perspective_code='p2', check_passed=False, details=CaaCheckResponseDetails(caa_record_present=False)),
                    CaaCheckResponse(perspective_code='p3', check_passed=True, details=CaaCheckResponseDetails(caa_record_present=False)),
                    CaaCheckResponse(perspective_code='p4', check_passed=True, details=CaaCheckResponseDetails(caa_record_present=False)),
                    CaaCheckResponse(perspective_code='p5', check_passed=True, details=CaaCheckResponseDetails(caa_record_present=False)),
                    CaaCheckResponse(perspective_code='p6', check_passed=True, details=CaaCheckResponseDetails(caa_record_present=False))
                ]
            case check_type.DCV:
                responses = [  # 2 false, using DNS Change method since that's in the request the test builder creates
                    DcvCheckResponse(perspective_code='p1', check_passed=True, details=DcvDnsChangeResponseDetails()),
                    DcvCheckResponse(perspective_code='p2', check_passed=True, details=DcvDnsChangeResponseDetails()),
                    DcvCheckResponse(perspective_code='p3', check_passed=True, details=DcvDnsChangeResponseDetails()),
                    DcvCheckResponse(perspective_code='p4', check_passed=True, details=DcvDnsChangeResponseDetails()),
                    DcvCheckResponse(perspective_code='p5', check_passed=False, details=DcvDnsChangeResponseDetails()),
                    DcvCheckResponse(perspective_code='p6', check_passed=False, details=DcvDnsChangeResponseDetails())
                ]

        return responses

    @pytest.mark.parametrize('check_type, perspective_count, quorum_count, is_valid_result', [
        (CheckType.CAA, 6, 4, True),
        (CheckType.DCV, 6, 5, False),  # higher quorum count
    ])
    def build_response__should_return_response_given_mpic_request_configuration_and_results(
            self, check_type, perspective_count, quorum_count, is_valid_result):
        perspective_responses = self.create_perspective_responses_given_check_type(check_type)
        request = ValidMpicRequestCreator.create_valid_mpic_request(check_type)
        mpic_response = MpicResponseBuilder.build_response(request, perspective_count, quorum_count, 2,
                                                           perspective_responses, is_valid_result)
        assert (mpic_response.request_orchestration_parameters.perspective_count ==
                request.orchestration_parameters.perspective_count)
        assert mpic_response.actual_orchestration_parameters.perspective_count == perspective_count
        assert mpic_response.actual_orchestration_parameters.quorum_count == quorum_count
        assert mpic_response.actual_orchestration_parameters.attempt_count == 2
        assert mpic_response.is_valid == is_valid_result
        assert mpic_response.perspectives == perspective_responses

    def build_response__should_include_validation_details_and_method_when_present_in_request_body(self):
        request = ValidMpicRequestCreator.create_valid_dcv_mpic_request()
        persp_responses_per_check_type = self.create_perspective_responses_given_check_type(CheckType.DCV)
        mpic_response = MpicResponseBuilder.build_response(request, 6, 5, 1,
                                                           persp_responses_per_check_type, False)
        assert mpic_response.dcv_check_parameters.validation_details.challenge_value == request.dcv_check_parameters.validation_details.challenge_value
        assert mpic_response.dcv_check_parameters.validation_details.validation_method == request.dcv_check_parameters.validation_details.validation_method


if __name__ == '__main__':
    pytest.main()
