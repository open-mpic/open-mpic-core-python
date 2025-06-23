import asyncio
import ipaddress
import time
import ssl
from ssl import TLSVersion
import traceback

import functools
import contextlib

from aiohttp import ClientError
from aiohttp.web import HTTPException
from cryptography import x509
from cryptography.x509.oid import ExtensionOID, NameOID

from open_mpic_core import DcvCheckRequest, DcvCheckResponse, DcvValidationMethod, DcvUtils
from open_mpic_core import MpicValidationError, ErrorMessages
from open_mpic_core import get_logger

logger = get_logger(__name__)


@contextlib.contextmanager
def getpeercert_with_binary_info():
    """
    Context manager that temporarily modifies SSL's getpeercert to add binary info binary_form=True
    """
    original_getpeercert = ssl.SSLObject.getpeercert

    # noinspection PyUnusedLocal
    @functools.wraps(original_getpeercert)
    def patched_getpeercert(self, binary_form=False):
        # Always call with binary_form=True and return the result
        return original_getpeercert(self, binary_form=True)

    try:
        # Apply the patch
        ssl.SSLObject.getpeercert = patched_getpeercert
        yield
    finally:
        # Always restore original, even if an exception occurs
        ssl.SSLObject.getpeercert = original_getpeercert


DCV_TLS_ALPN_ASN_1_OCTET_STRING_TYPE = b"\x04"
DCV_TLS_ALPN_ASN_1_OCTET_STRING_LENGTH = b"\x20"


class DcvTlsAlpnValidator:
    # See id-pe-acmeIdentifier in https://www.iana.org/assignments/smi-numbers/smi-numbers.xhtml
    ACME_TLS_ALPN_OID_DOTTED_STRING = "1.3.6.1.5.5.7.1.31"  # not found in cryptography.x509.oid list, so hardcoding
    ACME_TLS_ALPN_PROTOCOL = "acme-tls/1"

    def __init__(
        self,
        log_level: int | None = None,
    ):
        self.logger = logger.getChild(self.__class__.__name__)
        if log_level is not None:
            self.logger.setLevel(log_level)

    async def perform_tls_alpn_validation(self, request: DcvCheckRequest) -> DcvCheckResponse:
        validation_method = request.dcv_check_parameters.validation_method
        assert validation_method == DcvValidationMethod.ACME_TLS_ALPN_01
        key_authorization_hash = request.dcv_check_parameters.key_authorization_hash
        dcv_check_response = DcvUtils.create_empty_check_response(validation_method)
        hostname = request.domain_or_ip_target
        try:
            san_target = ipaddress.ip_address(hostname)
            sni_target = san_target.reverse_pointer  # this python std function doesn't have trailing dot
        except ValueError:
            sni_target = hostname
            san_target = hostname
        try:
            context = ssl.create_default_context()
            context.set_alpn_protocols([self.ACME_TLS_ALPN_PROTOCOL])
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            context.minimum_version = TLSVersion.TLSv1_2
            with getpeercert_with_binary_info():  # monkeypatch overrides default behavior and gets binary cert info
                reader, writer = await asyncio.open_connection(
                    hostname, 443, ssl=context, server_hostname=sni_target  # use the real host name  # pass in the context.
                )
                binary_cert = writer.get_extra_info("peercert")

            dcv_check_response.check_completed = True  # check will be considered "complete" whether it passes or fails

            x509_cert = x509.load_der_x509_certificate(binary_cert)

            subject_alt_name_extension = None
            acme_tls_alpn_extension = None
            
            for extension in x509_cert.extensions:
                if extension.oid.dotted_string == self.ACME_TLS_ALPN_OID_DOTTED_STRING:
                    acme_tls_alpn_extension = extension
                elif extension.oid == ExtensionOID.SUBJECT_ALTERNATIVE_NAME:
                    subject_alt_name_extension = extension
            # We need both of these extensions to proceed.
            if subject_alt_name_extension is None or acme_tls_alpn_extension is None:
                dcv_check_response.errors = [
                    MpicValidationError.create(ErrorMessages.TLS_ALPN_ERROR_CERTIFICATE_EXTENSION_MISSING)
                ]
            else:
                # We now know we have both extensions present. Begin checking each one.
                dcv_check_response.errors = self._validate_san_entry(subject_alt_name_extension, san_target)
                if not acme_tls_alpn_extension.critical:
                    # id-pe-acmeIdentifier extension needs to be critical
                    dcv_check_response.errors.append(
                        MpicValidationError.create(ErrorMessages.TLS_ALPN_ERROR_CERTIFICATE_ALPN_EXTENSION_NONCRITICAL)
                    )
                if len(dcv_check_response.errors) == 0:
                    # Check the id-pe-acmeIdentifier extension's value.
                    binary_challenge_seen = acme_tls_alpn_extension.value.value
                    try:
                        key_authorization_hash_binary = bytes.fromhex(key_authorization_hash)
                        # Add the first two ASN.1 encoding bytes to the expected hex string.
                        key_authorization_hash_binary = (
                            DCV_TLS_ALPN_ASN_1_OCTET_STRING_TYPE
                            + DCV_TLS_ALPN_ASN_1_OCTET_STRING_LENGTH
                            + key_authorization_hash_binary
                        )
                        self.logger.debug(f"tls-alpn-01: binary_challenge_seen: {binary_challenge_seen}")
                        self.logger.debug(f"tls-alpn-01: key_authorization_hash_binary: {key_authorization_hash_binary}")
                        
                    except ValueError:
                        dcv_check_response.errors = [
                            MpicValidationError.create(ErrorMessages.DCV_PARAMETER_ERROR, key_authorization_hash)
                        ]
                    else:
                        # Only assign the check_passed attribute if we properly parsed the challenge.
                        dcv_check_response.check_passed = binary_challenge_seen == key_authorization_hash_binary
                    
                    # Obtain the certs common name for logging.
                    common_name_attributes = x509_cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
                    common_name = None
                    if len(common_name_attributes) > 0:
                        common_name = str(common_name_attributes[0].value)
                        self.logger.debug(f"common name: {common_name}")
                    dcv_check_response.details.common_name = common_name # Cert common name for logging info.
                    
                    self.logger.debug(f"tls-alpn-01: passed? {dcv_check_response.check_passed}")
                dcv_check_response.timestamp_ns = time.time_ns()
        except asyncio.TimeoutError as e:
            dcv_check_response.timestamp_ns = time.time_ns()
            log_message = f"Timeout connecting to {hostname}: {str(e)}. Trace identifier: {request.trace_identifier}"
            self.logger.warning(log_message)
            message = f"Connection timed out while attempting to connect to {hostname}"
            dcv_check_response.errors = [
                MpicValidationError.create(ErrorMessages.DCV_LOOKUP_ERROR, e.__class__.__name__, message)
            ]
        except (ClientError, HTTPException, OSError) as e:
            self.logger.error(traceback.format_exc())
            dcv_check_response.timestamp_ns = time.time_ns()
            dcv_check_response.errors = [
                MpicValidationError.create(ErrorMessages.DCV_LOOKUP_ERROR, e.__class__.__name__, str(e))
            ]

        return dcv_check_response

    def _validate_san_entry(
        self, certificate_extension: x509.Extension, san_target: str | ipaddress.IPv4Address | ipaddress.IPv6Address
    ) -> list:
        errors = []
        # noinspection PyProtectedMember
        san_names = certificate_extension.value._general_names
        if len(san_names) != 1:
            errors = [MpicValidationError.create(ErrorMessages.TLS_ALPN_ERROR_CERTIFICATE_NO_SINGLE_SAN)]
        single_san_name = san_names[0]
        if type(san_target) == str:
            if not isinstance(single_san_name, x509.general_name.DNSName):
                errors = [MpicValidationError.create(ErrorMessages.TLS_ALPN_ERROR_CERTIFICATE_SAN_NOT_DNSNAME)]
            elif single_san_name.value.lower() != san_target.lower(): # Comparison is case insensitive per RFC4343 rules.
                errors = [MpicValidationError.create(ErrorMessages.TLS_ALPN_ERROR_CERTIFICATE_SAN_NOT_HOSTNAME)]
        else:
            if not isinstance(single_san_name, x509.general_name.IPAddress):
                errors = [MpicValidationError.create(ErrorMessages.TLS_ALPN_ERROR_CERTIFICATE_SAN_NOT_IPADDR)]
            elif single_san_name.value != san_target:
                errors = [MpicValidationError.create(ErrorMessages.TLS_ALPN_ERROR_CERTIFICATE_SAN_NOT_HOSTNAME)]
        self.logger.info("san value is hostname")
        return errors
