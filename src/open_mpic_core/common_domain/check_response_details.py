from typing import Union, Literal

from open_mpic_core.common_domain.enum.dcv_validation_method import DcvValidationMethod
from pydantic import BaseModel, Field
from typing_extensions import Annotated


class CaaCheckResponseDetails(BaseModel):
    caa_record_present: bool = False  # TODO allow None to reflect potential error state; rename to just 'present'?
    found_at: str | None = None  # domain where CAA record was found
    response: str | None = None  # base64 format of DNS RRset of response to CAA query


class DcvWebsiteChangeResponseDetails(BaseModel):
    validation_method: Literal[DcvValidationMethod.WEBSITE_CHANGE_V2] = DcvValidationMethod.WEBSITE_CHANGE_V2
    # response_history -- list of redirects given before final response found
    #    each redirect: status_code, url
    response_url: str | None = None
    response_status_code: int | None = None
    # response_page -- base64 encoding of first 100 bytes of page returned at final url
    # resolved_ip -- ip address used to communicate with domain_or_ip_target


class DcvDnsChangeResponseDetails(BaseModel):
    validation_method: Literal[DcvValidationMethod.DNS_CHANGE] = DcvValidationMethod.DNS_CHANGE
    # records_seen -- list of records found in DNS query; base 64 encoding of RRset
    # status_code -- dns response code
    # ad_flag -- boolean indicating if AD flag was set in DNS response


# class DcvAcmeHttp01ResponseDetails(BaseModel): same as DcvWebsiteChangeResponseDetails
# class DcvAcmeDns01ResponseDetails(BaseModel): same as DcvDnsChangeResponseDetails


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
