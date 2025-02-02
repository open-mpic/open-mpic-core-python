from typing import Union, Literal

from open_mpic_core.common_domain.check_response_details import CaaCheckResponseDetails, DcvCheckResponseDetails
from open_mpic_core.common_domain.validation_error import MpicValidationError
from open_mpic_core.common_domain.enum.check_type import CheckType
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

class DcvCheckResponseWithPerspectiveCode(CaaCheckResponse):
    perspective: str

CheckResponseWithPerspectiveCode = Union[CaaCheckResponseWithPerspectiveCode, DcvCheckResponseWithPerspectiveCode]

def add_perspective_code_to_check_response(check_response: CheckResponse, perspective_code: str) -> CheckResponseWithPerspectiveCode:
    if check_response.check_type == CheckType.CAA:
        return CaaCheckResponseWithPerspectiveCode(perspective_code=perspective_code, **check_response.__dict__)
    elif check_response.check_type == CheckType.DCV:
        return DcvCheckResponseWithPerspectiveCode(perspective_code=perspective_code, **check_response.__dict__)