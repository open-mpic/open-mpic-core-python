from abc import ABC
from typing import Union, Literal
from pydantic import BaseModel

from open_mpic_core import CheckType
from open_mpic_core import MpicEffectiveOrchestrationParameters, MpicRequestOrchestrationParameters
from open_mpic_core import CaaCheckParameters, DcvCheckParameters, PerspectiveResponse


class BaseMpicResponse(BaseModel, ABC):
    # The API specification version implemented by the coordinator that produced this response. Producers stamp this
    # with __api_version__; it defaults to None (rather than this library's version) so that a response parsed from
    # an older component that predates the field is not misattributed to the parsing component's version.
    api_version: str | None = None
    mpic_completed: bool | None = False
    request_orchestration_parameters: MpicRequestOrchestrationParameters | None = None
    actual_orchestration_parameters: MpicEffectiveOrchestrationParameters | None = None
    check_type: CheckType
    domain_or_ip_target: str | None = None
    is_valid: bool | None = False
    trace_identifier: str | None = None


class MpicCaaResponse(BaseMpicResponse):
    check_type: Literal[CheckType.CAA] = CheckType.CAA
    perspectives: list[PerspectiveResponse] | None = None
    caa_check_parameters: CaaCheckParameters | None = None
    previous_attempt_results: list[list[PerspectiveResponse]] | None = None


class MpicDcvResponse(BaseMpicResponse):
    check_type: Literal[CheckType.DCV] = CheckType.DCV
    perspectives: list[PerspectiveResponse] | None = None
    dcv_check_parameters: DcvCheckParameters | None = None
    previous_attempt_results: list[list[PerspectiveResponse]] | None = None


MpicResponse = Union[MpicCaaResponse, MpicDcvResponse]
