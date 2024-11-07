from abc import ABC
from typing import Literal, Union

from pydantic import BaseModel

from open_mpic_core.common_domain.enum.certificate_type import CertificateType
from open_mpic_core.common_domain.enum.dcv_validation_method import DcvValidationMethod
from open_mpic_core.common_domain.enum.dns_record_type import DnsRecordType
from open_mpic_core.common_domain.enum.url_scheme import UrlScheme


class CaaCheckParameters(BaseModel):
    certificate_type: CertificateType | None = None
    caa_domains: list[str] | None = None


class DcvValidationDetails(BaseModel, ABC):
    validation_method: DcvValidationMethod
    challenge_value: str
    # DNS records have 5 fields: name, ttl, class, type, rdata (which can be multipart itself)
    # A or AAAA: name=domain_name type=A <rdata:address> (ip address)
    # CNAME: name=domain_name_x type=CNAME <rdata:domain_name>
    # TXT: name=domain_name type=TXT <rdata:text> (freeform text)


class DcvWebsiteChangeValidationDetails(DcvValidationDetails):
    validation_method: Literal[DcvValidationMethod.WEBSITE_CHANGE_V2] = DcvValidationMethod.WEBSITE_CHANGE_V2
    http_token_path: str
    url_scheme: UrlScheme
    # TODO add optional flag to iterate up through the domain hierarchy


class DcvDnsChangeValidationDetails(DcvValidationDetails):
    validation_method: Literal[DcvValidationMethod.DNS_CHANGE] = DcvValidationMethod.DNS_CHANGE
    dns_name_prefix: str
    dns_record_type: DnsRecordType


# TODO DcvAcmeHttp01ValidationDetails
#      fields: token, key_authorization

# TODO DcvAcmeDns01ValidationDetails
#      fields: key_authorization


class DcvCheckParameters(BaseModel):
    validation_details: Union[DcvWebsiteChangeValidationDetails, DcvDnsChangeValidationDetails]
