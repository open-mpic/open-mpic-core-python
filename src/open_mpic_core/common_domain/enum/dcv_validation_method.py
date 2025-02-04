from enum import StrEnum


class DcvValidationMethod(StrEnum):
    WEBSITE_CHANGE = 'website-change'
    DNS_CHANGE = 'dns-change'  # CNAME, TXT, or CAA record
    ACME_HTTP_01 = 'acme-http-01'
    ACME_DNS_01 = 'acme-dns-01'  # TXT record
    CONTACT_EMAIL = 'contact-email'  # TXT or CAA record
    CONTACT_PHONE = 'contact-phone'  # TXT or CAA record
    IP_ADDRESS = 'ip-address'  # A or AAAA record
    ACME_TLS_ALPN_01 = 'acme-tls-alpn-01'  # not implemented yet
