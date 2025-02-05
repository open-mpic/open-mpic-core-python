from abc import ABC
from typing import Literal, Union, Any, Set, Annotated

from pydantic import BaseModel, field_validator, Discriminator, Tag

from open_mpic_core import CertificateType, DnsRecordType, DcvValidationMethod, UrlScheme


DNS_CHANGE_ALLOWED_RECORD_TYPES: Set[DnsRecordType] = {DnsRecordType.CNAME, DnsRecordType.TXT, DnsRecordType.CAA}
IP_ADDRESS_ALLOWED_RECORD_TYPES: Set[DnsRecordType] = {DnsRecordType.A, DnsRecordType.AAAA}


def dcv_discriminator(data: Any):
    """Two-level discriminator for DCV validation parameters.
    First checks validation_method, then for contact methods, checks dns_record_type."""
    if data is None:
        return None

    if isinstance(data, dict):
        validation_method = data.get("validation_method")
    else:
        validation_method = getattr(data, "validation_method")

    if validation_method == DcvValidationMethod.CONTACT_EMAIL:
        dns_record_type = data.get("dns_record_type") if isinstance(data, dict) else getattr(data, "dns_record_type")
        if dns_record_type == DnsRecordType.TXT:
            return "DcvContactEmailTxtValidationParameters"
        elif dns_record_type == DnsRecordType.CAA:
            return "DcvContactEmailCaaValidationParameters"
        raise ValueError(f"Invalid dns_record_type {dns_record_type} for contact email validation")

    elif validation_method == DcvValidationMethod.CONTACT_PHONE:
        dns_record_type = data.get("dns_record_type") if isinstance(data, dict) else getattr(data, "dns_record_type")
        if dns_record_type == DnsRecordType.TXT:
            return "DcvContactPhoneTxtValidationParameters"
        elif dns_record_type == DnsRecordType.CAA:
            return "DcvContactPhoneCaaValidationParameters"
        raise ValueError(f"Invalid dns_record_type {dns_record_type} for contact phone validation")

    # For other validation methods, just use the validation_method
    validation_class_map = {
        DcvValidationMethod.WEBSITE_CHANGE: "DcvWebsiteChangeValidationParameters",
        DcvValidationMethod.DNS_CHANGE: "DcvDnsChangeValidationParameters",
        DcvValidationMethod.IP_ADDRESS: "DcvIpAddressValidationParameters",
        DcvValidationMethod.ACME_HTTP_01: "DcvAcmeHttp01ValidationParameters",
        DcvValidationMethod.ACME_DNS_01: "DcvAcmeDns01ValidationParameters",
    }

    if validation_method in validation_class_map:
        return validation_class_map[validation_method]

    raise ValueError(f"Unknown validation method: {validation_method}")


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
    # dns_record_type: DnsRecordType = Union[DnsRecordType.CNAME, DnsRecordType.TXT, DnsRecordType.CAA]
    dns_record_type: DnsRecordType

    # noinspection PyNestedDecorators
    @field_validator("dns_record_type")
    @classmethod
    def validate_record_type(cls, v: DnsRecordType) -> DnsRecordType:
        if v not in DNS_CHANGE_ALLOWED_RECORD_TYPES:
            raise ValueError(f"Record type must be one of {DNS_CHANGE_ALLOWED_RECORD_TYPES}, got {v}")
        return v


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
    dns_record_type: DnsRecordType

    # noinspection PyNestedDecorators
    @field_validator("dns_record_type")
    @classmethod
    def validate_record_type(cls, v: DnsRecordType) -> DnsRecordType:
        if v not in IP_ADDRESS_ALLOWED_RECORD_TYPES:
            raise ValueError(f"Record type must be one of {IP_ADDRESS_ALLOWED_RECORD_TYPES}, got {v}")
        return v


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


DcvCheckParameters = Annotated[
    Union[
        Annotated[DcvWebsiteChangeValidationParameters, Tag("DcvWebsiteChangeValidationParameters")],
        Annotated[DcvDnsChangeValidationParameters, Tag("DcvDnsChangeValidationParameters")],
        Annotated[DcvAcmeHttp01ValidationParameters, Tag("DcvAcmeHttp01ValidationParameters")],
        Annotated[DcvAcmeDns01ValidationParameters, Tag("DcvAcmeDns01ValidationParameters")],
        Annotated[DcvContactEmailTxtValidationParameters, Tag("DcvContactEmailTxtValidationParameters")],
        Annotated[DcvContactEmailCaaValidationParameters, Tag("DcvContactEmailCaaValidationParameters")],
        Annotated[DcvContactPhoneTxtValidationParameters, Tag("DcvContactPhoneTxtValidationParameters")],
        Annotated[DcvContactPhoneCaaValidationParameters, Tag("DcvContactPhoneCaaValidationParameters")],
        Annotated[DcvIpAddressValidationParameters, Tag("DcvIpAddressValidationParameters")],
    ],
    Discriminator(dcv_discriminator),
]
