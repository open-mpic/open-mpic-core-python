from enum import StrEnum


class DcvValidationMethod(StrEnum):
    WEBSITE_CHANGE = 'website-change'
    DNS_CHANGE = 'dns-change'  # CNAME, TXT, or CAA record
    ACME_HTTP_01 = 'acme-http-01'
    ACME_DNS_01 = 'acme-dns-01'  # TXT record
    CONTACT_EMAIL_CAA = 'contact-email-caa'
    CONTACT_EMAIL_TXT = 'contact-email-txt'
    CONTACT_PHONE_CAA = 'contact-phone-caa'
    CONTACT_PHONE_TXT = 'contact-phone-txt'
    IP_ADDRESS = 'ip-address'  # A or AAAA record
    ACME_TLS_ALPN_01 = 'acme-tls-alpn-01'  # not implemented yet
    REVERSE_ADDRESS_LOOKUP = 'reverse-address-lookup'  # PTR record
