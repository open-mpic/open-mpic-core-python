from abc import ABC
from pydantic import BaseModel
from typing import Union, Literal

from open_mpic_core import CaaCheckResponseDetails, DcvCheckResponseDetails, MpicValidationError, CheckType


class BaseCheckResponse(BaseModel, ABC):
    check_completed: bool = False
    check_passed: bool = False
    errors: list[MpicValidationError] | None = None
    timestamp_ns: int | None = None


class CaaCheckResponse(BaseCheckResponse):
    check_type: Literal[CheckType.CAA] = CheckType.CAA
    # attestation -- object... digital signatures from remote perspective to allow result to be verified
    details: CaaCheckResponseDetails


class DcvCheckResponse(BaseCheckResponse):
    check_type: Literal[CheckType.DCV] = CheckType.DCV
    details: DcvCheckResponseDetails


CheckResponse = Union[CaaCheckResponse, DcvCheckResponse]
