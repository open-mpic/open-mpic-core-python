from enum import StrEnum


class DcvValidationMethod(StrEnum):
    WEBSITE_CHANGE_V2 = 'website-change-v2'
    DNS_CHANGE = 'dns-change'
    ACME_HTTP_01 = 'acme-http-01'
    ACME_DNS_01 = 'acme-dns-01'
    ACME_TLS_ALPN_01 = 'acme-tls-alpn-01'  # not implemented yet
