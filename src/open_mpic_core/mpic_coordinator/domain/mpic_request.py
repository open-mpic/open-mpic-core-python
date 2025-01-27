from abc import ABC
from typing import Literal, Union
from pydantic import BaseModel

from open_mpic_core import CheckType

from open_mpic_core import MpicRequestOrchestrationParameters, CaaCheckParameters, DcvCheckParameters


class BaseMpicRequest(BaseModel, ABC):
    domain_or_ip_target: str
    check_type: CheckType
    orchestration_parameters: MpicRequestOrchestrationParameters | None = None
    trace_identifier: str | None = None


class MpicCaaRequest(BaseMpicRequest):
    check_type: Literal[CheckType.CAA] = CheckType.CAA
    caa_check_parameters: CaaCheckParameters | None = None


class MpicDcvRequest(BaseMpicRequest):
    check_type: Literal[CheckType.DCV] = CheckType.DCV
    dcv_check_parameters: DcvCheckParameters


MpicRequest = Union[MpicCaaRequest, MpicDcvRequest]
