from typing import Union, Literal

from open_mpic_core.common_domain.enum.dcv_validation_method import DcvValidationMethod
from pydantic import BaseModel, Field
from typing_extensions import Annotated


class CaaCheckResponseDetails(BaseModel):
    caa_record_present: bool = False  # TODO allow None to reflect potential error state
    found_at: str | None = None
    response: str | None = None


class DcvWebsiteChangeResponseDetails(BaseModel):
    validation_method: Literal[DcvValidationMethod.WEBSITE_CHANGE_V2] = DcvValidationMethod.WEBSITE_CHANGE_V2


class DcvDnsChangeResponseDetails(BaseModel):
    validation_method: Literal[DcvValidationMethod.DNS_CHANGE] = DcvValidationMethod.DNS_CHANGE


DcvCheckResponseDetails = Annotated[Union[
    DcvWebsiteChangeResponseDetails, DcvDnsChangeResponseDetails
], Field(discriminator='validation_method')]


# utility class
class DcvCheckResponseDetailsBuilder:
    @staticmethod
    def build_response_details(validation_method: DcvValidationMethod) -> DcvCheckResponseDetails:
        types = {DcvValidationMethod.WEBSITE_CHANGE_V2: DcvWebsiteChangeResponseDetails,
                 DcvValidationMethod.DNS_CHANGE: DcvDnsChangeResponseDetails}
        return types[validation_method]()
