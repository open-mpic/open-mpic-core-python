from enum import StrEnum


class UrlScheme(StrEnum):
    HTTP = 'http'  # TODO caps or lowercase? check API spec...
    HTTPS = 'https'
