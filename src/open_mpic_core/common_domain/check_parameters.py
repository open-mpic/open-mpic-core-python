from abc import ABC
from typing import Literal, Union, Any, Set, Annotated

from pydantic import BaseModel, field_validator, Field

from open_mpic_core import CertificateType, DnsRecordType, DcvValidationMethod, UrlScheme


DNS_CHANGE_ALLOWED_RECORD_TYPES: Set[DnsRecordType] = {DnsRecordType.CNAME, DnsRecordType.TXT, DnsRecordType.CAA}
IP_ADDRESS_ALLOWED_RECORD_TYPES: Set[DnsRecordType] = {DnsRecordType.A, DnsRecordType.AAAA}


class CaaCheckParameters(BaseModel):
    certificate_type: CertificateType = CertificateType.TLS_SERVER
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
    dns_name_prefix: str | None = None
    dns_record_type: DnsRecordType


class DcvDnsChangeValidationParameters(DcvGeneralDnsValidationParameters):
    validation_method: Literal[DcvValidationMethod.DNS_CHANGE] = DcvValidationMethod.DNS_CHANGE
    dns_record_type: DnsRecordType
    require_exact_match: bool = False

    # noinspection PyNestedDecorators
    @field_validator("dns_record_type")
    @classmethod
    def validate_record_type(cls, v: DnsRecordType) -> DnsRecordType:
        if v not in DNS_CHANGE_ALLOWED_RECORD_TYPES:
            raise ValueError(f"Record type must be one of {DNS_CHANGE_ALLOWED_RECORD_TYPES}, got {v}")
        return v


class DcvContactEmailTxtValidationParameters(DcvGeneralDnsValidationParameters):
    validation_method: Literal[DcvValidationMethod.CONTACT_EMAIL_TXT] = DcvValidationMethod.CONTACT_EMAIL_TXT
    dns_record_type: Literal[DnsRecordType.TXT] = DnsRecordType.TXT
    dns_name_prefix: Literal["_validation-contactemail"] = "_validation-contactemail"


class DcvContactEmailCaaValidationParameters(DcvGeneralDnsValidationParameters):
    validation_method: Literal[DcvValidationMethod.CONTACT_EMAIL_CAA] = DcvValidationMethod.CONTACT_EMAIL_CAA
    dns_record_type: Literal[DnsRecordType.CAA] = DnsRecordType.CAA


class DcvContactPhoneTxtValidationParameters(DcvGeneralDnsValidationParameters):
    validation_method: Literal[DcvValidationMethod.CONTACT_PHONE_TXT] = DcvValidationMethod.CONTACT_PHONE_TXT
    dns_record_type: Literal[DnsRecordType.TXT] = DnsRecordType.TXT
    dns_name_prefix: Literal["_validation-contactphone"] = "_validation-contactphone"


class DcvContactPhoneCaaValidationParameters(DcvGeneralDnsValidationParameters):
    validation_method: Literal[DcvValidationMethod.CONTACT_PHONE_CAA] = DcvValidationMethod.CONTACT_PHONE_CAA
    dns_record_type: Literal[DnsRecordType.CAA] = DnsRecordType.CAA


class DcvIpAddressValidationParameters(DcvGeneralDnsValidationParameters):
    validation_method: Literal[DcvValidationMethod.IP_ADDRESS] = DcvValidationMethod.IP_ADDRESS
    dns_record_type: DnsRecordType

    # noinspection PyNestedDecorators
    @field_validator("dns_record_type")
    @classmethod
    def validate_record_type(cls, v: DnsRecordType) -> DnsRecordType:
        if v not in IP_ADDRESS_ALLOWED_RECORD_TYPES:
            raise ValueError(f"Record type must be one of {IP_ADDRESS_ALLOWED_RECORD_TYPES}, got {v}")
        return v


class DcvReverseAddressLookupValidationParameters(DcvGeneralDnsValidationParameters):
    validation_method: Literal[DcvValidationMethod.REVERSE_ADDRESS_LOOKUP] = DcvValidationMethod.REVERSE_ADDRESS_LOOKUP
    dns_record_type: Literal[DnsRecordType.PTR] = DnsRecordType.PTR


class DcvAcmeHttp01ValidationParameters(DcvValidationParameters):
    validation_method: Literal[DcvValidationMethod.ACME_HTTP_01] = DcvValidationMethod.ACME_HTTP_01
    token: str
    key_authorization: str
    http_headers: dict[str, Any] | None = None


class DcvAcmeDns01ValidationParameters(DcvValidationParameters):
    validation_method: Literal[DcvValidationMethod.ACME_DNS_01] = DcvValidationMethod.ACME_DNS_01
    key_authorization_hash: str
    dns_record_type: Literal[DnsRecordType.TXT] = DnsRecordType.TXT
    dns_name_prefix: Literal["_acme-challenge"] = "_acme-challenge"


DcvCheckParameters = Annotated[
    Union[
        DcvWebsiteChangeValidationParameters,
        DcvDnsChangeValidationParameters,
        DcvAcmeHttp01ValidationParameters,
        DcvAcmeDns01ValidationParameters,
        DcvContactEmailTxtValidationParameters,
        DcvContactEmailCaaValidationParameters,
        DcvContactPhoneTxtValidationParameters,
        DcvContactPhoneCaaValidationParameters,
        DcvIpAddressValidationParameters,
        DcvReverseAddressLookupValidationParameters,
    ],
    Field(discriminator="validation_method"),
]
