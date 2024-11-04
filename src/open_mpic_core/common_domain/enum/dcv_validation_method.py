from enum import StrEnum


class DcvValidationMethod(StrEnum):
    HTTP_GENERIC = 'http-generic'  # TODO rename to something better
    DNS_GENERIC = 'dns-generic'  # TODO rename to something better
    # WEBSITE_CHANGE_V2 = 'website-change-v2'  # HTTP (need to specify if HTTP or HTTPS)
    # ACME_HTTP_01 = 'acme-http-01'
    # ACME_DNS_01 = 'acme-dns-01'
    # ACME_TLS_ALPN_01 = 'acme-tls-alpn-01'
    # DNS_CHANGE = 'dns-change'
