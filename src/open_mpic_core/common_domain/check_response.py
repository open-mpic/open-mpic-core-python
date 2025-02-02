from typing import Union, Literal

from open_mpic_core import CaaCheckResponseDetails, DcvCheckResponseDetails, MpicValidationError, CheckType
from pydantic import BaseModel


class BaseCheckResponse(BaseModel):
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


class CaaCheckResponseWithPerspectiveCode(CaaCheckResponse):
    perspective: str

class DcvCheckResponseWithPerspectiveCode(DcvCheckResponse):
    perspective: str

CheckResponseWithPerspectiveCode = Union[CaaCheckResponseWithPerspectiveCode, DcvCheckResponseWithPerspectiveCode]

def add_perspective_code_to_check_response(check_response: CheckResponse, perspective_code: str) -> CheckResponseWithPerspectiveCode:
    if check_response.check_type == CheckType.CAA:
        return CaaCheckResponseWithPerspectiveCode(perspective=perspective_code, **check_response.__dict__)
    elif check_response.check_type == CheckType.DCV:
        return DcvCheckResponseWithPerspectiveCode(perspective=perspective_code, **check_response.__dict__)