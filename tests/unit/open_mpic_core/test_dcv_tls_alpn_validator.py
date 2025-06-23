import ipaddress
import logging
import pytest
import ssl
import socket
from unittest.mock import MagicMock
from io import StringIO
from cryptography import x509
from cryptography.x509 import SubjectAlternativeName, Extension, NameAttribute
from cryptography.x509.oid import ExtensionOID

from open_mpic_core import ErrorMessages, TRACE_LEVEL
from open_mpic_core import DcvTlsAlpnValidator

from unit.test_util.valid_check_creator import ValidCheckCreator


# noinspection PyMethodMayBeStatic
class TestDcvTlsAlpnValidator:
    @pytest.fixture(autouse=True)
    def setup_validator(self):
        # noinspection PyAttributeOutsideInit
        self.validator = DcvTlsAlpnValidator()
        yield self.validator

    @pytest.fixture(autouse=True)
    def setup_logging(self):
        # Clear existing handlers
        root = logging.getLogger()
        for handler in root.handlers[:]:
            root.removeHandler(handler)

        # noinspection PyAttributeOutsideInit
        self.log_output = StringIO()  # to be able to inspect what gets logged
        handler = logging.StreamHandler(self.log_output)
        handler.setFormatter(logging.Formatter("%(asctime)s - %(name)s - %(levelname)s - %(message)s"))

        # Configure fresh logging
        logging.basicConfig(level=TRACE_LEVEL, handlers=[handler])
        yield

    def constructor__should_set_log_level_if_provided(self):
        validator = DcvTlsAlpnValidator(log_level=logging.ERROR)
        assert validator.logger.level == logging.ERROR

    async def perform_tls_alpn_validation__should_pass_with_valid_certificate(self, mocker):
        dcv_request = ValidCheckCreator.create_valid_acme_tls_alpn_01_check_request()
        mock_cert = self._create_mock_certificate(
            dcv_request.domain_or_ip_target, dcv_request.dcv_check_parameters.key_authorization_hash
        )
        self._mock_socket_and_ssl_context(mocker, mock_cert)
        response = await self.validator.perform_tls_alpn_validation(dcv_request)
        assert response.check_completed is True
        assert response.check_passed is True
        assert not response.errors

    async def perform_tls_alpn_validation__should_pass_with_valid_certificate_for_ip(self, mocker):
        dcv_request = ValidCheckCreator.create_valid_acme_tls_alpn_01_check_request("2001:0DB8::19ca:3311")
        mock_cert = self._create_mock_certificate_with_ip_san(
            dcv_request.domain_or_ip_target, dcv_request.dcv_check_parameters.key_authorization_hash
        )
        self._mock_socket_and_ssl_context(mocker, mock_cert)
        response = await self.validator.perform_tls_alpn_validation(dcv_request)
        assert response.check_completed is True
        assert response.check_passed is True
        assert not response.errors

    async def perform_tls_alpn_validation__should_include_common_name_in_successful_response(self, mocker):
        dcv_request = ValidCheckCreator.create_valid_acme_tls_alpn_01_check_request()
        mock_cert = self._create_mock_certificate(
            dcv_request.domain_or_ip_target, dcv_request.dcv_check_parameters.key_authorization_hash
        )
        self._mock_socket_and_ssl_context(mocker, mock_cert)
        response = await self.validator.perform_tls_alpn_validation(dcv_request)
        assert response.check_completed is True
        assert response.check_passed is True
        assert response.details.common_name == dcv_request.domain_or_ip_target

    async def perform_tls_alpn_validation__should_fail_if_required_extensions_are_missing(self, mocker):
        dcv_request = ValidCheckCreator.create_valid_acme_tls_alpn_01_check_request()
        mock_cert = self._create_mock_certificate_without_extensions()
        self._mock_socket_and_ssl_context(mocker, mock_cert)
        response = await self.validator.perform_tls_alpn_validation(dcv_request)
        assert response.check_completed is True
        assert response.check_passed is False
        assert len(response.errors) == 1
        assert response.errors[0].error_message == ErrorMessages.TLS_ALPN_ERROR_CERTIFICATE_EXTENSION_MISSING.message

    async def perform_tls_alpn_validation__should_fail_given_invalid_san_entry(self, mocker):
        dcv_request = ValidCheckCreator.create_valid_acme_tls_alpn_01_check_request()
        key_authorization_hash = dcv_request.dcv_check_parameters.key_authorization_hash
        hostname = dcv_request.domain_or_ip_target
        mock_cert = self._create_mock_certificate_with_non_dns_san_entry(hostname, key_authorization_hash)
        self._mock_socket_and_ssl_context(mocker, mock_cert)
        response = await self.validator.perform_tls_alpn_validation(dcv_request)
        assert response.check_completed is True
        assert response.check_passed is False
        assert len(response.errors) > 0
        assert response.errors[0].error_message == ErrorMessages.TLS_ALPN_ERROR_CERTIFICATE_SAN_NOT_DNSNAME.message

    async def perform_tls_alpn_validation__should_fail_with_ip_in_dns_name(self, mocker):
        dcv_request = ValidCheckCreator.create_valid_acme_tls_alpn_01_check_request("1.2.3.4")
        mock_cert = self._create_mock_certificate(
            dcv_request.domain_or_ip_target, dcv_request.dcv_check_parameters.key_authorization_hash
        )
        self._mock_socket_and_ssl_context(mocker, mock_cert)
        response = await self.validator.perform_tls_alpn_validation(dcv_request)
        assert response.check_completed is True
        assert response.check_passed is False
        assert len(response.errors) > 0
        assert response.errors[0].error_message == ErrorMessages.TLS_ALPN_ERROR_CERTIFICATE_SAN_NOT_IPADDR.message

    async def perform_tls_alpn_validation__should_fail_given_multiple_san_entries(self, mocker):
        dcv_request = ValidCheckCreator.create_valid_acme_tls_alpn_01_check_request()
        key_authorization_hash = dcv_request.dcv_check_parameters.key_authorization_hash
        hostname = dcv_request.domain_or_ip_target
        mock_cert = self._create_mock_certificate_with_multiple_san_entries(hostname, key_authorization_hash)
        self._mock_socket_and_ssl_context(mocker, mock_cert)
        response = await self.validator.perform_tls_alpn_validation(dcv_request)
        assert response.check_completed is True
        assert response.check_passed is False
        assert len(response.errors) > 0
        assert response.errors[0].error_message == ErrorMessages.TLS_ALPN_ERROR_CERTIFICATE_NO_SINGLE_SAN.message

    async def perform_tls_alpn_validation__should_fail_given_nonmatching_san_entry(self, mocker):
        dcv_request = ValidCheckCreator.create_valid_acme_tls_alpn_01_check_request()
        key_authorization_hash = dcv_request.dcv_check_parameters.key_authorization_hash
        hostname = dcv_request.domain_or_ip_target
        mock_cert = self._create_mock_certificate_with_nonmatching_san_entry(hostname, key_authorization_hash)
        self._mock_socket_and_ssl_context(mocker, mock_cert)
        response = await self.validator.perform_tls_alpn_validation(dcv_request)
        assert response.check_completed is True
        assert response.check_passed is False
        assert len(response.errors) > 0
        assert response.errors[0].error_message == ErrorMessages.TLS_ALPN_ERROR_CERTIFICATE_SAN_NOT_HOSTNAME.message

    async def perform_tls_alpn_validation__should_fail_given_noncritical_alpn_extension(self, mocker):
        dcv_request = ValidCheckCreator.create_valid_acme_tls_alpn_01_check_request()
        mock_cert = self._create_mock_certificate_with_noncritical_alpn_extension(
            dcv_request.domain_or_ip_target, dcv_request.dcv_check_parameters.key_authorization_hash
        )
        self._mock_socket_and_ssl_context(mocker, mock_cert)
        response = await self.validator.perform_tls_alpn_validation(dcv_request)
        assert response.check_completed is True
        assert response.check_passed is False
        assert len(response.errors) > 0
        assert response.errors[0].error_message == ErrorMessages.TLS_ALPN_ERROR_CERTIFICATE_ALPN_EXTENSION_NONCRITICAL.message

    async def perform_tls_alpn_validation__should_fail_given_invalid_key_authorization_hash(self, mocker):
        dcv_request = ValidCheckCreator.create_valid_acme_tls_alpn_01_check_request()
        hostname = dcv_request.domain_or_ip_target
        key_authorization_hash = dcv_request.dcv_check_parameters.key_authorization_hash
        mock_cert = self._create_mock_certificate(hostname, key_authorization_hash)
        # Modify the mock certificate to have a different key authorization hash
        dcv_request.dcv_check_parameters.key_authorization_hash = 'invalid_hash_value'
        self._mock_socket_and_ssl_context(mocker, mock_cert)
        response = await self.validator.perform_tls_alpn_validation(dcv_request)
        assert response.check_completed is True
        assert response.check_passed is False
        expected_error = ErrorMessages.DCV_PARAMETER_ERROR.message.format("invalid_hash_value")
        assert response.errors[0].error_message == expected_error

    async def perform_tls_alpn_validation__should_handle_connection_errors(self, mocker):
        dcv_request = ValidCheckCreator.create_valid_acme_tls_alpn_01_check_request()
        # Mock asyncio to raise an exception (haven't checked if this specific exception could be raised, but whatever)
        mocker.patch('asyncio.open_connection', side_effect=socket.timeout("Connection timed out"))
        response = await self.validator.perform_tls_alpn_validation(dcv_request)
        assert response.check_completed is False
        assert response.check_passed is False
        assert len(response.errors) == 1

    async def perform_tls_alpn_validation__should_handle_ssl_errors(self, mocker):
        dcv_request = ValidCheckCreator.create_valid_acme_tls_alpn_01_check_request()
        # Mock SSL context to raise an exception
        mocker.patch('ssl.create_default_context', side_effect=ssl.SSLError("SSL error"))
        response = await self.validator.perform_tls_alpn_validation(dcv_request)
        assert response.check_completed is False
        assert response.check_passed is False
        assert len(response.errors) == 1

    def _create_mock_certificate(self, hostname, key_authorization_hash):
        # Create a mock certificate with the required extensions
        mock_cert = MagicMock()

        dns_name = x509.general_name.DNSName(hostname)

        san_extension_value = SubjectAlternativeName(general_names=[dns_name])
        san_extension = Extension(oid=ExtensionOID.SUBJECT_ALTERNATIVE_NAME, critical=False, value=san_extension_value)

        key_auth_hash_binary = bytes.fromhex(key_authorization_hash)
        assert len(key_auth_hash_binary) == 32, "Key authorization hash must be 32 bytes long"
        acme_extension = MagicMock()
        acme_extension.oid.dotted_string = self.validator.ACME_TLS_ALPN_OID_DOTTED_STRING
        acme_extension.critical = True
        acme_extension.value.value = b"\x04\x20" + key_auth_hash_binary

        mock_cert.extensions = [san_extension, acme_extension]

        # mock common name as require by test case
        mock_cert.subject = x509.Name(attributes=[x509.NameAttribute(x509.NameOID.COMMON_NAME, hostname)])

        return mock_cert

    def _create_mock_certificate_without_extensions(self):
        mock_cert = MagicMock()
        mock_cert.extensions = []
        return mock_cert

    def _create_mock_certificate_with_multiple_san_entries(self, hostname, key_authorization_hash):
        mock_cert = self._create_mock_certificate(hostname, key_authorization_hash)
        # Create multiple SAN entries
        san_extension = mock_cert.extensions[0]
        mock_dns_name1 = x509.general_name.DNSName(hostname)
        mock_dns_name2 = x509.general_name.DNSName("another.example.com")
        san_extension.value._general_names = [mock_dns_name1, mock_dns_name2]
        return mock_cert

    def _create_mock_certificate_with_non_dns_san_entry(self, hostname, key_authorization_hash):
        mock_cert = self._create_mock_certificate(hostname, key_authorization_hash)
        # Create bad SAN entry
        san_extension = mock_cert.extensions[0]
        invalid_san = "bad.san"
        san_extension.value._general_names = [invalid_san]
        return mock_cert

    def _create_mock_certificate_with_nonmatching_san_entry(self, hostname, key_authorization_hash):
        mock_cert = self._create_mock_certificate(hostname, key_authorization_hash)
        # Create a SAN entry that does not match the hostname
        san_extension = mock_cert.extensions[0]
        invalid_san = x509.general_name.DNSName("invalid.example.com")
        san_extension.value._general_names = [invalid_san]
        return mock_cert
    
    def _create_mock_certificate_with_ip_san(self, ipstring, key_authorization_hash):
        mock_cert = self._create_mock_certificate('foo.baa', key_authorization_hash)
        # Create a SAN entry that does not match the hostname
        san_extension = mock_cert.extensions[0]
        ip_san = x509.general_name.IPAddress(ipaddress.ip_address(ipstring))
        san_extension.value._general_names = [ip_san]
        return mock_cert
    
    def _create_mock_certificate_with_noncritical_alpn_extension(self, hostname, key_authorization_hash):
        mock_cert = self._create_mock_certificate(hostname, key_authorization_hash)
        alpn_extension = mock_cert.extensions[1]
        alpn_extension.critical = False
        return mock_cert

    def _mock_socket_and_ssl_context(self, mocker, mock_cert):
        # Mock socket.create_connection
        mock_writer = MagicMock()
        mock_reader = MagicMock()
        mocker.patch('asyncio.open_connection', return_value=(mock_reader, mock_writer))

        mock_writer.get_extra_info.return_value = mock_cert
        # Mock SSL context and wrapped socket
        #mock_ssl_socket = MagicMock()
        #mock_ssl_socket.getpeercert.return_value = b'mock_binary_cert'

        ## Mock SSL context's wrap_socket method
        #mock_context = MagicMock()
        #mock_context.wrap_socket.return_value.__enter__.return_value = mock_ssl_socket
        #mocker.patch('ssl.create_default_context', return_value=mock_context)

        # Mock x509.load_der_x509_certificate to return our mock certificate
        mocker.patch('cryptography.x509.load_der_x509_certificate', return_value=mock_cert)

        return mock_writer
