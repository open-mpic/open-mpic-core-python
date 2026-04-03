from abc import ABC
from typing import Literal, Union, Any, Set, Annotated
from uritools import isuri

from pydantic import BaseModel, field_validator, Field, model_validator

from open_mpic_core import CertificateType, DnsRecordType, DcvValidationMethod, UrlScheme
from open_mpic_core.common_domain.enum import dns_record_type

DNS_CHANGE_ALLOWED_RECORD_TYPES: Set[DnsRecordType] = {DnsRecordType.CNAME, DnsRecordType.TXT, DnsRecordType.CAA}
IP_ADDRESS_ALLOWED_RECORD_TYPES: Set[DnsRecordType] = {DnsRecordType.A, DnsRecordType.AAAA}


class CaaCheckParameters(BaseModel):
    certificate_type: CertificateType = CertificateType.TLS_SERVER
    caa_domains: list[str] | None = None
    allow_lookup_failure: bool = False  # Baseline Requirements have a carve-out for CAA lookup failure; use carefully!


class DcvValidationParameters(BaseModel, ABC):
    validation_method: DcvValidationMethod
    require_exact_case: bool
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
    require_exact_case: bool = True
    # TODO add optional flag to iterate up through the domain hierarchy


class DcvGeneralDnsValidationParameters(DcvValidationParameters, ABC):
    challenge_value: str
    dns_name_prefix: str | None = None
    dns_record_type: DnsRecordType


class DcvDnsChangeValidationParameters(DcvGeneralDnsValidationParameters):
    validation_method: Literal[DcvValidationMethod.DNS_CHANGE] = DcvValidationMethod.DNS_CHANGE
    require_exact_match: bool = False  # if False, looks for a matching substring (rather than entire string)
    require_exact_case: bool = True

    # noinspection PyNestedDecorators
    @field_validator("dns_record_type")
    @classmethod
    def validate_record_type(cls, v: DnsRecordType) -> DnsRecordType:
        if v not in DNS_CHANGE_ALLOWED_RECORD_TYPES:
            raise ValueError(f"Record type must be one of {DNS_CHANGE_ALLOWED_RECORD_TYPES}, got {v}")
        return v

    @model_validator(mode="after")
    def validate_require_exact_case(self) -> 'DcvDnsChangeValidationParameters':
        if self.dns_record_type is not DnsRecordType.TXT:
            self.require_exact_case = False  # case-sensitivity only applies to TXT records; force to False for others
        return self


class DcvDnsPersistentValidationParameters(DcvValidationParameters):
    validation_method: Literal[DcvValidationMethod.DNS_PERSISTENT] = DcvValidationMethod.DNS_PERSISTENT
    dns_record_type: Literal[DnsRecordType.TXT] = DnsRecordType.TXT
    dns_name_prefix: Literal["_validation-persist"] = "_validation-persist"
    issuer_domain_names: list[str]  # Disclosed issuer domain names from CA's CP/CPS
    expected_account_uri: str  # The specific account URI to validate
    require_exact_case: bool = Field(default=False, strict=False)

    @field_validator("expected_account_uri")
    @classmethod
    def validate_account_uri(cls, v: str) -> str:
        if not isuri(v):
            raise ValueError(f"expected_account_uri must be a valid URI, got {v}")
        return v

    @field_validator("issuer_domain_names")
    @classmethod
    def validate_issuer_domain_names(cls, v: list[str]) -> list[str]:
        if not v:
            raise ValueError("issuer_domain_names must be a non-empty list of domain names")
        for domain in v:
            # check that v is non-empty
            if not domain:
                raise ValueError("issuer_domain_names must not contain empty strings")
        return v


class DcvContactEmailTxtValidationParameters(DcvGeneralDnsValidationParameters):
    validation_method: Literal[DcvValidationMethod.CONTACT_EMAIL_TXT] = DcvValidationMethod.CONTACT_EMAIL_TXT
    dns_record_type: Literal[DnsRecordType.TXT] = DnsRecordType.TXT
    dns_name_prefix: Literal["_validation-contactemail"] = "_validation-contactemail"
    require_exact_case: bool = Field(default=False, strict=False)


class DcvContactEmailCaaValidationParameters(DcvGeneralDnsValidationParameters):
    validation_method: Literal[DcvValidationMethod.CONTACT_EMAIL_CAA] = DcvValidationMethod.CONTACT_EMAIL_CAA
    dns_record_type: Literal[DnsRecordType.CAA] = DnsRecordType.CAA
    require_exact_case: bool = Field(default=False, strict=False)


class DcvContactPhoneTxtValidationParameters(DcvGeneralDnsValidationParameters):
    validation_method: Literal[DcvValidationMethod.CONTACT_PHONE_TXT] = DcvValidationMethod.CONTACT_PHONE_TXT
    dns_record_type: Literal[DnsRecordType.TXT] = DnsRecordType.TXT
    dns_name_prefix: Literal["_validation-contactphone"] = "_validation-contactphone"
    require_exact_case: bool = Field(default=False, strict=False)


class DcvContactPhoneCaaValidationParameters(DcvGeneralDnsValidationParameters):
    validation_method: Literal[DcvValidationMethod.CONTACT_PHONE_CAA] = DcvValidationMethod.CONTACT_PHONE_CAA
    dns_record_type: Literal[DnsRecordType.CAA] = DnsRecordType.CAA
    require_exact_case: bool = Field(default=False, strict=False)


class DcvIpAddressValidationParameters(DcvGeneralDnsValidationParameters):
    validation_method: Literal[DcvValidationMethod.IP_ADDRESS] = DcvValidationMethod.IP_ADDRESS
    dns_record_type: DnsRecordType
    require_exact_case: bool = Field(default=False, strict=False)

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
    require_exact_case: bool = Field(default=False, strict=False)


class DcvAcmeHttp01ValidationParameters(DcvValidationParameters):
    validation_method: Literal[DcvValidationMethod.ACME_HTTP_01] = DcvValidationMethod.ACME_HTTP_01
    token: str
    key_authorization: str
    http_headers: dict[str, Any] | None = None
    require_exact_case: bool = Field(default=True, strict=True)


class DcvAcmeDns01ValidationParameters(DcvValidationParameters):
    validation_method: Literal[DcvValidationMethod.ACME_DNS_01] = DcvValidationMethod.ACME_DNS_01
    key_authorization_hash: str
    dns_record_type: Literal[DnsRecordType.TXT] = DnsRecordType.TXT
    dns_name_prefix: Literal["_acme-challenge"] = "_acme-challenge"
    require_exact_case: bool = Field(default=True, strict=True)


class DcvAcmeTlsAlpn01ValidationParameters(DcvValidationParameters):
    validation_method: Literal[DcvValidationMethod.ACME_TLS_ALPN_01] = DcvValidationMethod.ACME_TLS_ALPN_01
    key_authorization_hash: str
    require_exact_case: bool = Field(default=False, strict=False)


DcvCheckParameters = Annotated[
    Union[
        DcvWebsiteChangeValidationParameters,
        DcvDnsChangeValidationParameters,
        DcvDnsPersistentValidationParameters,
        DcvAcmeHttp01ValidationParameters,
        DcvAcmeDns01ValidationParameters,
        DcvAcmeTlsAlpn01ValidationParameters,
        DcvContactEmailTxtValidationParameters,
        DcvContactEmailCaaValidationParameters,
        DcvContactPhoneTxtValidationParameters,
        DcvContactPhoneCaaValidationParameters,
        DcvIpAddressValidationParameters,
        DcvReverseAddressLookupValidationParameters,
    ],
    Field(discriminator="validation_method"),
]
