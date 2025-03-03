from abc import ABC
from typing import Union

from pydantic import BaseModel

from open_mpic_core import CaaCheckParameters, DcvCheckParameters


class BaseCheckRequest(BaseModel, ABC):
    domain_or_ip_target: str
    trace_identifier: str | None = None


class CaaCheckRequest(BaseCheckRequest):
    caa_check_parameters: CaaCheckParameters | None = None


class DcvCheckRequest(BaseCheckRequest):
    dcv_check_parameters: DcvCheckParameters


CheckRequest = Union[CaaCheckRequest, DcvCheckRequest]
