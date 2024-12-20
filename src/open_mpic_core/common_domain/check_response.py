from typing import Union, Literal

from open_mpic_core.common_domain.check_response_details import CaaCheckResponseDetails, DcvCheckResponseDetails
from open_mpic_core.common_domain.validation_error import MpicValidationError
from open_mpic_core.common_domain.enum.check_type import CheckType
from pydantic import BaseModel, Field
from typing_extensions import Annotated


class BaseCheckResponse(BaseModel):
    perspective_code: str
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
