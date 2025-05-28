from enum import Enum


class ErrorMessages(Enum):
    CAA_LOOKUP_ERROR = ('mpic_error:caa_checker:lookup', 'There was an error looking up the CAA record: {0}')
    DCV_LOOKUP_ERROR = ('mpic_error:dcv_checker:lookup', 'There was an error looking up the DCV record. Error type: {0}, Error message: {1}')
    DCV_PARAMETER_ERROR = ('mpic_error:dcv_checker:parameter:key_authorization_hash', 'The provided key_authorization_hash contained invalid characters: {0}')
    COORDINATOR_COMMUNICATION_ERROR = ('mpic_error:coordinator:communication', 'Communication with the remote perspective failed.')
    COORDINATOR_REMOTE_CHECK_ERROR = ('mpic_error:coordinator:remote_check', 'The remote check failed to complete: {0}')
    TOO_MANY_FAILED_PERSPECTIVES_ERROR = ('mpic_error:coordinator:too_many_failed_perspectives', 'Too many perspectives failed to complete the check.')
    GENERAL_HTTP_ERROR = ('mpic_error:http', 'An HTTP error occurred: Response status {0}, Response reason: {1}')
    INVALID_REDIRECT_ERROR = ('mpic_error:redirect:invalid', 'Invalid redirect. Redirect code: {0}, target: {1}')
    COHORT_CREATION_ERROR = ('mpic_error:coordinator:cohort', 'The coordinator could not construct a cohort of size {0}')

    TLS_ALPN_ERROR_CERTIFICATE_EXTENSION_MISSING = ('mpic_error:dcv_checker:tls_alpn:certificate:extension_missing', 'The TLS ALPN certificate was missing an extension.')
    TLS_ALPN_ERROR_CERTIFICATE_ALPN_EXTENSION_NONCRITICAL = ('mpic_error:dcv_checker:tls_alpn:certificate:noncritical_alpn_extension', 'The TLS ALPN certificate has non-critical id-pe-acmeIdentifier extension')
    TLS_ALPN_ERROR_CERTIFICATE_NO_SINGLE_SAN = ('mpic_error:dcv_checker:tls_alpn:certificate:no_single_san', 'The TLS ALPN certificate must have a single SAN entry.')
    TLS_ALPN_ERROR_CERTIFICATE_SAN_NOT_DNSNAME = ('mpic_error:dcv_checker:tls_alpn:certificate:san_not_dnsname', 'Target was a domain name, but the TLS ALPN certificate SAN was not a DNSName.')
    TLS_ALPN_ERROR_CERTIFICATE_SAN_NOT_IPADDR = ('mpic_error:dcv_checker:tls_alpn:certificate:san_type_not_match', 'Target was an IP address, but the TLS ALPN certificate SAN was not an IP address.')
    TLS_ALPN_ERROR_CERTIFICATE_SAN_NOT_HOSTNAME = ('mpic_error:dcv_checker:tls_alpn:certificate:san_not_hostname', 'The TLS ALPN certificate SAN was not equal to the hostname being validated.')

    def __init__(self, key, message):
        self.key = key
        self.message = message
