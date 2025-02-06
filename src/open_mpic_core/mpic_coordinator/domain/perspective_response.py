from pydantic import BaseModel

from open_mpic_core import CheckResponse


class PerspectiveResponse(BaseModel):
    perspective_code: str
    check_response: CheckResponse
