from typing import List
from open_mpic_core.mpic_coordinator.domain.mpic_orchestration_parameters import MpicEffectiveOrchestrationParameters
from open_mpic_core.mpic_coordinator.domain.mpic_request import BaseMpicRequest, MpicDcvRequest
from open_mpic_core.mpic_coordinator.domain.mpic_response import MpicCaaResponse, MpicDcvResponse, MpicResponse
from open_mpic_core.common_domain.check_response import CheckResponseWithPerspectiveCode

class MpicResponseBuilder:
    @staticmethod
    def build_response(request: BaseMpicRequest, perspective_count: int, quorum_count: int, attempts: int,
                       perspective_responses: List[CheckResponseWithPerspectiveCode], is_result_valid: bool, previous_attempt_results) -> MpicResponse:
        actual_orchestration_parameters = MpicEffectiveOrchestrationParameters(
            perspective_count=perspective_count,
            quorum_count=quorum_count,
            attempt_count=attempts
        )

        if type(request) is MpicDcvRequest:  # type() instead of isinstance() because of inheritance
            response = MpicDcvResponse(
                dcv_check_parameters=request.dcv_check_parameters,
            )
        else:
            response = MpicCaaResponse(
                caa_check_parameters=request.caa_check_parameters,
            )

        response.domain_or_ip_target=request.domain_or_ip_target
        response.request_orchestration_parameters = request.orchestration_parameters
        response.actual_orchestration_parameters = actual_orchestration_parameters
        response.is_valid = is_result_valid
        response.perspectives = perspective_responses
        response.trace_identifier = request.trace_identifier
        response.previous_attempt_results = previous_attempt_results

        return response
