from abc import ABC
from typing import Literal, Union, Any

from pydantic import BaseModel

from open_mpic_core import CertificateType, DnsRecordType, DcvValidationMethod, UrlScheme


class CaaCheckParameters(BaseModel):
    certificate_type: CertificateType
    caa_domains: list[str] | None = None
    # contact_info_query: bool | False = False  # to better accommodate email/phone based DCV using contact info in CAA


class DcvValidationParameters(BaseModel, ABC):
    validation_method: DcvValidationMethod
    # DNS records have 5 fields: name, ttl, class, type, rdata (which can be multipart itself)
    # A or AAAA: name=domain_name type=A <rdata:address> (ip address)
    # CNAME: name=domain_name_x type=CNAME <rdata:domain_name>
    # TXT: name=domain_name type=TXT <rdata:text> (freeform text)


class DcvWebsiteChangeValidationParameters(DcvValidationParameters):
    validation_method: Literal[DcvValidationMethod.WEBSITE_CHANGE] = DcvValidationMethod.WEBSITE_CHANGE
    challenge_value: str
    http_token_path: str
    url_scheme: UrlScheme = UrlScheme.HTTP
    http_headers: dict[str, Any] | None = None
    match_regex: str | None = None
    # TODO add optional flag to iterate up through the domain hierarchy


class DcvGeneralDnsValidationParameters(DcvValidationParameters, ABC):
    challenge_value: str
    require_exact_match: bool = False
    dns_name_prefix: str | None = None
    dns_record_type: DnsRecordType


class DcvDnsChangeValidationParameters(DcvGeneralDnsValidationParameters):
    validation_method: Literal[DcvValidationMethod.DNS_CHANGE] = DcvValidationMethod.DNS_CHANGE
    dns_record_type: DnsRecordType = Union[DnsRecordType.CNAME, DnsRecordType.TXT, DnsRecordType.CAA]


class DcvContactEmailTxtValidationParameters(DcvGeneralDnsValidationParameters):
    validation_method: Literal[DcvValidationMethod.CONTACT_EMAIL] = DcvValidationMethod.CONTACT_EMAIL
    dns_record_type: Literal[DnsRecordType.TXT] = DnsRecordType.TXT
    dns_name_prefix: Literal["_validation-contactemail"] = "_validation-contactemail"


class DcvContactEmailCaaValidationParameters(DcvGeneralDnsValidationParameters):
    validation_method: Literal[DcvValidationMethod.CONTACT_EMAIL] = DcvValidationMethod.CONTACT_EMAIL
    dns_record_type: Literal[DnsRecordType.CAA] = DnsRecordType.CAA


class DcvContactPhoneTxtValidationParameters(DcvGeneralDnsValidationParameters):
    validation_method: Literal[DcvValidationMethod.CONTACT_PHONE] = DcvValidationMethod.CONTACT_PHONE
    dns_record_type: Literal[DnsRecordType.TXT] = DnsRecordType.TXT
    dns_name_prefix: Literal["_validation-contactphone"] = "_validation-contactphone"


class DcvContactPhoneCaaValidationParameters(DcvGeneralDnsValidationParameters):
    validation_method: Literal[DcvValidationMethod.CONTACT_PHONE] = DcvValidationMethod.CONTACT_PHONE
    dns_record_type: Literal[DnsRecordType.CAA] = DnsRecordType.CAA


class DcvIpAddressValidationParameters(DcvGeneralDnsValidationParameters):
    validation_method: Literal[DcvValidationMethod.IP_ADDRESS] = DcvValidationMethod.IP_ADDRESS
    dns_record_type: DnsRecordType = Union[DnsRecordType.A, DnsRecordType.AAAA]


class DcvAcmeHttp01ValidationParameters(DcvValidationParameters):
    validation_method: Literal[DcvValidationMethod.ACME_HTTP_01] = DcvValidationMethod.ACME_HTTP_01
    token: str
    key_authorization: str
    http_headers: dict[str, Any] | None = None


class DcvAcmeDns01ValidationParameters(DcvValidationParameters):
    validation_method: Literal[DcvValidationMethod.ACME_DNS_01] = DcvValidationMethod.ACME_DNS_01
    key_authorization: str
    dns_record_type: Literal[DnsRecordType.TXT] = DnsRecordType.TXT
    dns_name_prefix: Literal["_acme-challenge"] = "_acme-challenge"


DcvCheckParameters = Union[
    DcvWebsiteChangeValidationParameters,
    DcvDnsChangeValidationParameters,
    DcvAcmeHttp01ValidationParameters,
    DcvAcmeDns01ValidationParameters,
    DcvContactEmailTxtValidationParameters,
    DcvContactEmailCaaValidationParameters,
    DcvContactPhoneTxtValidationParameters,
    DcvContactPhoneCaaValidationParameters,
    DcvIpAddressValidationParameters,
]
