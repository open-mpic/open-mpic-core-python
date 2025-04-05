from open_mpic_core import (
    DcvWebsiteChangeValidationParameters,
    DcvDnsChangeValidationParameters,
    CaaCheckParameters,
    DcvAcmeHttp01ValidationParameters,
    DcvAcmeDns01ValidationParameters,
    DcvIpAddressValidationParameters,
    DcvContactEmailCaaValidationParameters,
    DcvContactEmailTxtValidationParameters,
    DcvContactPhoneCaaValidationParameters,
    DcvContactPhoneTxtValidationParameters,
    DcvReverseAddressLookupValidationParameters,
    DcvCheckRequest,
    CaaCheckRequest,
    CertificateType,
    DcvValidationMethod,
    DnsRecordType,
    UrlScheme,
)


class ValidCheckCreator:
    @staticmethod
    def create_valid_caa_check_request() -> CaaCheckRequest:
        return CaaCheckRequest(
            domain_or_ip_target="example.com",
            caa_check_parameters=CaaCheckParameters(
                certificate_type=CertificateType.TLS_SERVER, caa_domains=["ca1.com"]
            ),
        )

    @staticmethod
    def create_valid_http_check_request() -> DcvCheckRequest:
        return DcvCheckRequest(
            domain_or_ip_target="example.com",
            dcv_check_parameters=DcvWebsiteChangeValidationParameters(
                http_token_path="token111_ca1.txt", challenge_value="challenge_111", url_scheme=UrlScheme.HTTP
            ),
        )

    @staticmethod
    def create_valid_dns_check_request(record_type=DnsRecordType.TXT) -> DcvCheckRequest:
        check_request = DcvCheckRequest(
            domain_or_ip_target="example.com",
            dcv_check_parameters=DcvDnsChangeValidationParameters(
                dns_name_prefix="_dnsauth",
                dns_record_type=record_type,
                challenge_value=f"{record_type}_challenge_111.ca1.com.",
            ),
        )
        return check_request

    @staticmethod
    def create_valid_contact_check_request(validation_method: DcvValidationMethod) -> DcvCheckRequest:
        match validation_method:
            case DcvValidationMethod.CONTACT_EMAIL_CAA:
                check_parameters = DcvContactEmailCaaValidationParameters(
                    challenge_value="validate.me@example.com", dns_name_prefix=""
                )
            case DcvValidationMethod.CONTACT_EMAIL_TXT:
                check_parameters = DcvContactEmailTxtValidationParameters(challenge_value=f"validate.me@example.com")
            case DcvValidationMethod.CONTACT_PHONE_CAA:
                check_parameters = DcvContactPhoneCaaValidationParameters(
                    challenge_value="555-555-5555", dns_name_prefix=""
                )
            case _:  # CONTACT_PHONE_TXT
                check_parameters = DcvContactPhoneTxtValidationParameters(challenge_value="555-555-5555")
        check_request = DcvCheckRequest(domain_or_ip_target="example.com", dcv_check_parameters=check_parameters)
        # check_request.dcv_check_parameters.require_exact_match = True
        return check_request

    @staticmethod
    def create_valid_ip_lookup_check_request(record_type=DnsRecordType.A) -> DcvCheckRequest:
        check_request = DcvCheckRequest(
            domain_or_ip_target="example.com",
            dcv_check_parameters=DcvIpAddressValidationParameters(
                dns_name_prefix="_dnsauth", dns_record_type=record_type, challenge_value="challenge_111"
            ),
        )
        challenge_value = "192.0.2.1" if record_type == DnsRecordType.A else "2001:db8::1"  # A or AAAA
        check_request.dcv_check_parameters.challenge_value = challenge_value
        return check_request

    @staticmethod
    def create_valid_acme_http_01_check_request() -> DcvCheckRequest:
        return DcvCheckRequest(
            domain_or_ip_target="example.com",
            dcv_check_parameters=DcvAcmeHttp01ValidationParameters(
                token="token111_ca1", key_authorization="challenge_111"
            ),
        )

    @staticmethod
    def create_valid_acme_dns_01_check_request():
        return DcvCheckRequest(
            domain_or_ip_target="example.com",
            dcv_check_parameters=DcvAcmeDns01ValidationParameters(key_authorization_hash="challenge_111"),
        )

    @staticmethod
    def create_valid_reverse_address_lookup_check_request() -> DcvCheckRequest:
        # a PTR record will have a trailing dot in the value
        return DcvCheckRequest(
            domain_or_ip_target="192.0.2.1.in-addr.arpa",
            dcv_check_parameters=DcvReverseAddressLookupValidationParameters(challenge_value="challenge_111."),
        )

    @staticmethod
    def create_valid_dcv_check_request(validation_method: DcvValidationMethod, record_type=DnsRecordType.TXT):
        match validation_method:
            case DcvValidationMethod.WEBSITE_CHANGE:
                return ValidCheckCreator.create_valid_http_check_request()
            case DcvValidationMethod.DNS_CHANGE:
                return ValidCheckCreator.create_valid_dns_check_request(record_type)
            case DcvValidationMethod.ACME_HTTP_01:
                return ValidCheckCreator.create_valid_acme_http_01_check_request()
            case DcvValidationMethod.ACME_DNS_01:
                return ValidCheckCreator.create_valid_acme_dns_01_check_request()
            case DcvValidationMethod.IP_ADDRESS:
                return ValidCheckCreator.create_valid_ip_lookup_check_request(record_type)
            case DcvValidationMethod.REVERSE_ADDRESS_LOOKUP:
                return ValidCheckCreator.create_valid_reverse_address_lookup_check_request()
            case (
                DcvValidationMethod.CONTACT_EMAIL_CAA
                | DcvValidationMethod.CONTACT_EMAIL_TXT
                | DcvValidationMethod.CONTACT_PHONE_CAA
                | DcvValidationMethod.CONTACT_PHONE_TXT
            ):
                return ValidCheckCreator.create_valid_contact_check_request(validation_method)
