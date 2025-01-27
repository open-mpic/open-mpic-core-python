from abc import ABC
from typing import Union, Literal
from pydantic import BaseModel

from open_mpic_core import CheckType
from open_mpic_core import CaaCheckResponse, DcvCheckResponse, CaaCheckParameters, DcvCheckParameters
from open_mpic_core import MpicRequestOrchestrationParameters, MpicEffectiveOrchestrationParameters


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
