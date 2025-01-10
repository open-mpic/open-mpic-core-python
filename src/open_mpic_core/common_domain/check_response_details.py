from typing import Union, Literal

from open_mpic_core.common_domain.enum.dcv_validation_method import DcvValidationMethod
from pydantic import BaseModel


class CaaCheckResponseDetails(BaseModel):
    caa_record_present: bool | None = None  # was a CAA record found (None indicates N/A, e.g. due to error)
    found_at: str | None = None  # domain where CAA record was found
    records_seen: list[str] | None = None  # list of records found in DNS query


class RedirectResponse(BaseModel):
    status_code: int
    url: str  # rename to location?


class DcvHttpCheckResponseDetails(BaseModel):
    validation_method: Literal[DcvValidationMethod.WEBSITE_CHANGE_V2, DcvValidationMethod.ACME_HTTP_01]
    response_history: list[RedirectResponse] | None = None  # list of redirects followed to final page
    response_url: str | None = None
    response_status_code: int | None = None
    response_page: str | None = None  # Base64 encoded first 100 bytes of page returned at final url
    # resolved_ip -- ip address used to communicate with domain_or_ip_target


class DcvDnsCheckResponseDetails(BaseModel):
    validation_method: Literal[DcvValidationMethod.DNS_CHANGE,
                               DcvValidationMethod.IP_LOOKUP,
                               DcvValidationMethod.CONTACT_EMAIL,
                               DcvValidationMethod.CONTACT_PHONE,
                               DcvValidationMethod.ACME_DNS_01]
    records_seen: list[str] | None = None  # list of records found in DNS query; not base64 encoded
    response_code: int | None = None  # DNS response code
    ad_flag: bool | None = None  # was AD flag set in DNS response
    found_at: str | None = None  # domain where DNS record was found


DcvCheckResponseDetails = Union[DcvHttpCheckResponseDetails, DcvDnsCheckResponseDetails]


# utility class
class DcvCheckResponseDetailsBuilder:
    @staticmethod
    def build_response_details(validation_method: DcvValidationMethod) -> DcvCheckResponseDetails:
        types = {DcvValidationMethod.WEBSITE_CHANGE_V2: DcvHttpCheckResponseDetails,
                 DcvValidationMethod.DNS_CHANGE: DcvDnsCheckResponseDetails,
                 DcvValidationMethod.ACME_HTTP_01: DcvHttpCheckResponseDetails,
                 DcvValidationMethod.ACME_DNS_01: DcvDnsCheckResponseDetails,
                 DcvValidationMethod.CONTACT_PHONE: DcvDnsCheckResponseDetails,
                 DcvValidationMethod.CONTACT_EMAIL: DcvDnsCheckResponseDetails,
                 DcvValidationMethod.IP_LOOKUP: DcvDnsCheckResponseDetails}
        return types[validation_method](validation_method=validation_method)
