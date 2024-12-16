from abc import ABC
from typing import Literal, Union, Any

from pydantic import BaseModel

from open_mpic_core.common_domain.enum.certificate_type import CertificateType
from open_mpic_core.common_domain.enum.dcv_validation_method import DcvValidationMethod
from open_mpic_core.common_domain.enum.dns_record_type import DnsRecordType
from open_mpic_core.common_domain.enum.url_scheme import UrlScheme


class CaaCheckParameters(BaseModel):
    certificate_type: CertificateType | None = None
    caa_domains: list[str] | None = None
    # contact_info_query: bool | False = False  # to better accommodate email/phone based DCV using contact info in CAA


class DcvValidationDetails(BaseModel, ABC):
    validation_method: DcvValidationMethod
    # DNS records have 5 fields: name, ttl, class, type, rdata (which can be multipart itself)
    # A or AAAA: name=domain_name type=A <rdata:address> (ip address)
    # CNAME: name=domain_name_x type=CNAME <rdata:domain_name>
    # TXT: name=domain_name type=TXT <rdata:text> (freeform text)


class DcvWebsiteChangeValidationDetails(DcvValidationDetails):
    validation_method: Literal[DcvValidationMethod.WEBSITE_CHANGE_V2] = DcvValidationMethod.WEBSITE_CHANGE_V2
    challenge_value: str
    http_token_path: str
    url_scheme: UrlScheme = UrlScheme.HTTP
    http_headers: dict[str, Any] | None = None
    # TODO add optional flag to iterate up through the domain hierarchy


class DcvGeneralDnsValidationDetails(DcvValidationDetails, ABC):
    challenge_value: str
    require_exact_match: bool = True
    dns_name_prefix: str
    dns_record_type: DnsRecordType


class DcvDnsChangeValidationDetails(DcvGeneralDnsValidationDetails):
    validation_method: Literal[DcvValidationMethod.DNS_CHANGE] = DcvValidationMethod.DNS_CHANGE
    dns_record_type: DnsRecordType = Union[DnsRecordType.CNAME, DnsRecordType.TXT, DnsRecordType.CAA]


class DcvContactEmailTxtValidationDetails(DcvGeneralDnsValidationDetails):
    validation_method: Literal[DcvValidationMethod.CONTACT_EMAIL] = DcvValidationMethod.CONTACT_EMAIL
    dns_record_type: Literal[DnsRecordType.TXT] = DnsRecordType.TXT
    dns_name_prefix: Literal['_validation-contactemail'] = '_validation-contactemail'


class DcvContactEmailCaaValidationDetails(DcvGeneralDnsValidationDetails):
    validation_method: Literal[DcvValidationMethod.CONTACT_EMAIL] = DcvValidationMethod.CONTACT_EMAIL
    dns_record_type: Literal[DnsRecordType.CAA] = DnsRecordType.CAA


class DcvContactPhoneTxtValidationDetails(DcvGeneralDnsValidationDetails):
    validation_method: Literal[DcvValidationMethod.CONTACT_PHONE] = DcvValidationMethod.CONTACT_PHONE
    dns_record_type: Literal[DnsRecordType.TXT] = DnsRecordType.TXT
    dns_name_prefix: Literal['_validation-contactphone'] = '_validation-contactphone'


class DcvContactPhoneCaaValidationDetails(DcvGeneralDnsValidationDetails):
    validation_method: Literal[DcvValidationMethod.CONTACT_PHONE] = DcvValidationMethod.CONTACT_PHONE
    dns_record_type: Literal[DnsRecordType.CAA] = DnsRecordType.CAA


class DcvIpLookupValidationDetails(DcvGeneralDnsValidationDetails):
    validation_method: Literal[DcvValidationMethod.IP_LOOKUP] = DcvValidationMethod.IP_LOOKUP
    dns_record_type: DnsRecordType = Union[DnsRecordType.A, DnsRecordType.AAAA]


class DcvAcmeHttp01ValidationDetails(DcvValidationDetails):
    validation_method: Literal[DcvValidationMethod.ACME_HTTP_01] = DcvValidationMethod.ACME_HTTP_01
    token: str
    key_authorization: str
    http_headers: dict[str, Any] | None = None


class DcvAcmeDns01ValidationDetails(DcvValidationDetails):
    validation_method: Literal[DcvValidationMethod.ACME_DNS_01] = DcvValidationMethod.ACME_DNS_01
    key_authorization: str
    dns_record_type: Literal[DnsRecordType.TXT] = DnsRecordType.TXT
    dns_name_prefix: Literal['_acme-challenge'] = '_acme-challenge'


class DcvCheckParameters(BaseModel):
    validation_details: Union[
        DcvWebsiteChangeValidationDetails,
        DcvDnsChangeValidationDetails,
        DcvAcmeHttp01ValidationDetails,
        DcvAcmeDns01ValidationDetails,
        DcvContactEmailTxtValidationDetails,
        DcvContactEmailCaaValidationDetails,
        DcvContactPhoneTxtValidationDetails,
        DcvContactPhoneCaaValidationDetails,
        DcvIpLookupValidationDetails
    ]
