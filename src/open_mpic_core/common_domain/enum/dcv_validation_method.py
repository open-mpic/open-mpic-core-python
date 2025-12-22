from enum import StrEnum


class DcvValidationMethod(StrEnum):
    WEBSITE_CHANGE = 'website-change'  # CABF BRs 3.2.2.4.18 Agreed-Upon Change to Website v2
    DNS_CHANGE = 'dns-change'  # CNAME, TXT, or CAA record
    DNS_PERSISTENT = 'dns-persistent'  # CABF BRs 3.2.2.4.22 DNS TXT Record with Persistent Value
    ACME_HTTP_01 = 'acme-http-01'  # CABF BRs 3.2.2.4.19 Agreed-Upon Change to Website - ACME
    ACME_DNS_01 = 'acme-dns-01'  # TXT record
    ACME_TLS_ALPN_01 = 'acme-tls-alpn-01'  # CABF BRs 3.2.2.4.20 TLS Using ALPN
    DNS_ACCOUNT_01 = 'dns-account-01'  # CABF BRs 3.2.2.4.21 DNS Labeled with Account ID - ACME TODO not yet implemented
    CONTACT_EMAIL_CAA = 'contact-email-caa'
    CONTACT_EMAIL_TXT = 'contact-email-txt'
    CONTACT_PHONE_CAA = 'contact-phone-caa'
    CONTACT_PHONE_TXT = 'contact-phone-txt'
    IP_ADDRESS = 'ip-address'  # A or AAAA record
    REVERSE_ADDRESS_LOOKUP = 'reverse-address-lookup'  # PTR record
