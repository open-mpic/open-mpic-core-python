from typing import List
from open_mpic_core import MpicEffectiveOrchestrationParameters
from open_mpic_core import MpicRequest, MpicDcvRequest
from open_mpic_core import MpicCaaResponse, MpicDcvResponse, MpicResponse
from open_mpic_core import PerspectiveResponse


class MpicResponseBuilder:
    @staticmethod
    def build_response(
        request: MpicRequest,
        perspective_count: int,
        quorum_count: int,
        attempts: int,
        perspective_responses: List[PerspectiveResponse],
        is_result_valid: bool,
        previous_attempt_results,
    ) -> MpicResponse:
        actual_orchestration_parameters = MpicEffectiveOrchestrationParameters(
            perspective_count=perspective_count, quorum_count=quorum_count, attempt_count=attempts
        )

        if type(request) is MpicDcvRequest:  # type() instead of isinstance() because of inheritance
            response = MpicDcvResponse(
                dcv_check_parameters=request.dcv_check_parameters,
            )
        else:
            response = MpicCaaResponse(
                caa_check_parameters=request.caa_check_parameters,
            )

        response.domain_or_ip_target = request.domain_or_ip_target
        response.request_orchestration_parameters = request.orchestration_parameters
        response.actual_orchestration_parameters = actual_orchestration_parameters
        response.is_valid = is_result_valid
        response.perspectives = perspective_responses
        response.trace_identifier = request.trace_identifier
        response.previous_attempt_results = previous_attempt_results
        response.mpic_completed = MpicResponseBuilder.enough_perspectives_completed(
            perspective_count, perspective_responses, quorum_count
        )

        return response

    @staticmethod
    def enough_perspectives_completed(perspective_count, perspective_responses, quorum_count):
        perspectives_not_completed = len(
            [response for response in perspective_responses if not response.check_response.check_completed]
        )
        # if <=5 perspectives, 1 perspective failure-to-complete allowed; if >5, 2 failures-to-complete allowed
        enough_perspectives_completed = perspectives_not_completed <= perspective_count - quorum_count
        return enough_perspectives_completed
