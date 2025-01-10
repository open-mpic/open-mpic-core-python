from abc import ABC
from typing import Union, Literal

from open_mpic_core.common_domain.enum.check_type import CheckType
from pydantic import BaseModel, Field

from open_mpic_core.common_domain.check_response import CaaCheckResponse, DcvCheckResponse
from open_mpic_core.mpic_coordinator.domain.mpic_orchestration_parameters import MpicEffectiveOrchestrationParameters
from open_mpic_core.mpic_coordinator.domain.mpic_orchestration_parameters import MpicRequestOrchestrationParameters
from open_mpic_core.common_domain.check_parameters import CaaCheckParameters, DcvCheckParameters
from typing_extensions import Annotated


class BaseMpicResponse(BaseModel, ABC):
    request_orchestration_parameters: MpicRequestOrchestrationParameters | None = None
    actual_orchestration_parameters: MpicEffectiveOrchestrationParameters | None = None
    check_type: CheckType
    domain_or_ip_target: str | None = None
    is_valid: bool | None = False
    trace_identifier: str | None = None


class MpicCaaResponse(BaseMpicResponse):
    check_type: Literal[CheckType.CAA] = CheckType.CAA
    perspectives: list[CaaCheckResponse] | None = None
    caa_check_parameters: CaaCheckParameters | None = None
    previous_attempt_results: list[list[CaaCheckResponse]] | None = None


class MpicDcvResponse(BaseMpicResponse):
    check_type: Literal[CheckType.DCV] = CheckType.DCV
    perspectives: list[DcvCheckResponse] | None = None
    dcv_check_parameters: DcvCheckParameters | None = None
    previous_attempt_results: list[list[DcvCheckResponse]] | None = None


MpicResponse = Union[MpicCaaResponse, MpicDcvResponse]
