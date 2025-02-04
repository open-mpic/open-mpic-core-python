import pytest

from open_mpic_core import (
    CaaCheckResponse,
    DcvCheckResponse,
    CaaCheckResponseDetails,
    DcvCheckResponseDetailsBuilder,
    CheckType,
    DcvValidationMethod,
    MpicResponseBuilder,
    PerspectiveResponse
)

from unit.test_util.valid_mpic_request_creator import ValidMpicRequestCreator


class TestMpicResponseBuilder:
    @staticmethod
    def create_perspective_responses_given_check_type(check_type=CheckType.DCV, validation_method=None):
        responses = {}
        match check_type:
            case check_type.CAA:
                # 1 false out of 6
                perspective_status_map = {"p1": True, "p2": False, "p3": True, "p4": True, "p5": True, "p6": True}
                responses = list(
                    map(
                        lambda code: PerspectiveResponse(
                            perspective_code=code,
                            check_response=CaaCheckResponse(
                                check_passed=perspective_status_map[code],
                                details=CaaCheckResponseDetails(caa_record_present=(not perspective_status_map[code])),
                            )
                        ),
                        perspective_status_map.keys(),
                    )
                )
            case check_type.DCV:
                response_details = DcvCheckResponseDetailsBuilder.build_response_details(validation_method)
                # 2 false out of 6
                perspective_status_map = {"p1": True, "p2": True, "p3": True, "p4": True, "p5": False, "p6": False}
                responses = list(
                    map(
                        lambda code: PerspectiveResponse(
                            perspective_code=code,
                            check_response=DcvCheckResponse(
                                check_passed=perspective_status_map[code], details=response_details
                            )
                        ),
                        perspective_status_map.keys(),
                    )
                )

        return responses

    @pytest.mark.parametrize(
        "check_type, perspective_count, quorum_count, is_valid_result, validation_method",
        [
            (CheckType.CAA, 6, 4, True, None),
            (CheckType.DCV, 6, 5, False, DcvValidationMethod.DNS_CHANGE),  # higher quorum count
        ],
    )
    def build_response__should_return_response_given_mpic_request_configuration_and_results(
        self, check_type, perspective_count, quorum_count, is_valid_result, validation_method
    ):
        perspective_responses = self.create_perspective_responses_given_check_type(check_type, validation_method)
        request = ValidMpicRequestCreator.create_valid_mpic_request(check_type, validation_method)
        mpic_response = MpicResponseBuilder.build_response(
            request, perspective_count, quorum_count, 2, perspective_responses, is_valid_result, None
        )
        assert mpic_response.request_orchestration_parameters.perspective_count == perspective_count
        assert mpic_response.actual_orchestration_parameters.perspective_count == perspective_count
        assert mpic_response.actual_orchestration_parameters.quorum_count == quorum_count
        assert mpic_response.actual_orchestration_parameters.attempt_count == 2
        assert mpic_response.is_valid == is_valid_result
        assert mpic_response.perspectives == perspective_responses

    def build_response__should_include_validation_parameters_and_method_when_present_in_request_body(self):
        request = ValidMpicRequestCreator.create_valid_dcv_mpic_request()
        persp_responses_per_check_type = self.create_perspective_responses_given_check_type(
            CheckType.DCV, DcvValidationMethod.DNS_CHANGE
        )
        mpic_response = MpicResponseBuilder.build_response(
            request, 6, 5, 1, persp_responses_per_check_type, False, None
        )
        challenge_value = request.dcv_check_parameters.challenge_value
        assert challenge_value == mpic_response.dcv_check_parameters.challenge_value
        validation_method = request.dcv_check_parameters.validation_method
        assert validation_method == mpic_response.dcv_check_parameters.validation_method

    def build_response__should_include_previous_attempt_results_when_present(self):
        request = ValidMpicRequestCreator.create_valid_dcv_mpic_request()
        persp_responses_per_check_type = self.create_perspective_responses_given_check_type(
            CheckType.DCV, DcvValidationMethod.DNS_CHANGE
        )
        previous_attempt_results = [persp_responses_per_check_type]
        mpic_response = MpicResponseBuilder.build_response(
            request, 6, 5, 1, persp_responses_per_check_type, False, previous_attempt_results
        )
        assert mpic_response.previous_attempt_results == previous_attempt_results


if __name__ == "__main__":
    pytest.main()
