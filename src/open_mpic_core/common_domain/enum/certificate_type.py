from enum import StrEnum


class CertificateType(StrEnum):
    TLS_SERVER = 'tls-server'
    S_MIME = 's-mime'
