import asyncio
import time
import socket
import ssl
import traceback

from aiohttp import ClientError
from aiohttp.web import HTTPException
from cryptography import x509
from cryptography.x509.oid import ExtensionOID

from open_mpic_core import DcvCheckRequest, DcvCheckResponse, DcvValidationMethod, DcvUtils
from open_mpic_core import MpicValidationError, ErrorMessages
from open_mpic_core import get_logger

logger = get_logger(__name__)


class DcvTlsAlpnValidator:
    # See id-pe-acmeIdentifier in https://www.iana.org/assignments/smi-numbers/smi-numbers.xhtml
    ACME_TLS_ALPN_OID_DOTTED_STRING = "1.3.6.1.5.5.7.1.31"  # not found in cryptography.x509.oid list, so hardcoding
    ACME_TLS_ALPN_PROTOCOL = "acme-tls/1"

    def __init__(
        self,
        log_level: int = None,
    ):
        self.logger = logger.getChild(self.__class__.__name__)
        if log_level is not None:
            self.logger.setLevel(log_level)

    async def perform_tls_alpn_validation(self, request: DcvCheckRequest) -> DcvCheckResponse:
        self.logger.info("!!!!! entering alpn block")
        validation_method = request.dcv_check_parameters.validation_method
        assert validation_method == DcvValidationMethod.ACME_TLS_ALPN_01
        key_authorization_hash = request.dcv_check_parameters.key_authorization_hash
        self.logger.info("!!!!! before response builder")
        dcv_check_response = DcvUtils.create_empty_check_response(validation_method)
        hostname = request.domain_or_ip_target

        try:
            self.logger.info("!!!!! try alpn block")
            self.logger.info(f"hostname: {hostname}")
            context = ssl.create_default_context()
            context.set_alpn_protocols([self.ACME_TLS_ALPN_PROTOCOL])
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE

            with socket.create_connection((hostname, 443)) as generic_tls_connection:
                self.logger.info("!!!!! first with (created 443 connection)")
                dcv_check_response.check_completed = True  # If we made the socket, we can mark the check as completed.
                with context.wrap_socket(generic_tls_connection, server_hostname=hostname) as tls_alpn_connection:
                    self.logger.info("!!!!! second with (wrapped connection in tls alpn context)")
                    binary_cert = tls_alpn_connection.getpeercert(binary_form=True)
                    x509_cert = x509.load_der_x509_certificate(binary_cert)
                    self.logger.info("x509_cert from binary form.")

                    subject_alt_name_extension = None
                    acme_tls_alpn_extension = None

                    for extension in x509_cert.extensions:
                        if extension.oid.dotted_string == self.ACME_TLS_ALPN_OID_DOTTED_STRING:
                            acme_tls_alpn_extension = extension
                        elif extension.oid.dotted_string == ExtensionOID.SUBJECT_ALTERNATIVE_NAME.dotted_string:
                            subject_alt_name_extension = extension
                    self.logger.info("all indexes expanded.")
                    # We need both of these extensions to proceed.
                    if subject_alt_name_extension is None or acme_tls_alpn_extension is None:
                        dcv_check_response.errors = [
                            MpicValidationError.create(ErrorMessages.TLS_ALPN_ERROR_CERTIFICATE_EXTENSION_MISSING)
                        ]
                    else:
                        self.logger.info("both extensions found")
                        # We now know we have both extensions present. Begin checking each one.
                        dcv_check_response.errors = self._validate_san_entry(subject_alt_name_extension, hostname)
                        if len(dcv_check_response.errors) == 0:
                            # Check the id-pe-acmeIdentifier extension.
                            binary_challenge_seen = acme_tls_alpn_extension.value.value
                            key_authorization_hash_binary = None
                            try:
                                key_authorization_hash_binary = bytes.fromhex(key_authorization_hash)
                                self.logger.info(f"binary_challenge_seen: {binary_challenge_seen}")
                                self.logger.info(f"key_authorization_hash_binary: {key_authorization_hash_binary}")
                                # Add the first two ASN.1 encoding bytes to the expected hex string.
                                key_authorization_hash_binary = b"\x04\x20" + key_authorization_hash_binary
                            except ValueError:
                                dcv_check_response.errors = [
                                    MpicValidationError.create(
                                        ErrorMessages.DCV_PARAMETER_ERROR, key_authorization_hash
                                    )
                                ]
                            dcv_check_response.check_passed = binary_challenge_seen == key_authorization_hash_binary
                            self.logger.info(f"key hash test passed? {dcv_check_response.check_passed}")
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

    def _validate_san_entry(self, certificate_extension: x509.Extension, hostname: str) -> list:
        errors = []
        # noinspection PyProtectedMember
        san_names = certificate_extension.value._general_names
        if len(san_names) != 1:
            errors = [MpicValidationError.create(ErrorMessages.TLS_ALPN_ERROR_CERTIFICATE_NO_SINGLE_SAN)]
        single_san_name = san_names[0]
        if not isinstance(single_san_name, x509.general_name.DNSName):
            errors = [MpicValidationError.create(ErrorMessages.TLS_ALPN_ERROR_CERTIFICATE_SAN_NOT_DNSNAME)]
        elif single_san_name.value != hostname:
            errors = [MpicValidationError.create(ErrorMessages.TLS_ALPN_ERROR_CERTIFICATE_SAN_NOT_HOSTNAME)]
        self.logger.info("san value is hostname")
        return errors
