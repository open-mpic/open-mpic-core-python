import base64
import hashlib


class Acme:
    ACME_CHALLENGE_LABEL = "_acme-challenge"

    @staticmethod
    def dns_account_label_from_url(acme_account_url: str) -> str:
        """
        Derive the per-account DNS label for dns-account-01 per draft-ietf-acme-dns-account-label:
        base32(SHA-256(ACCOUNT_URL)[0:10]), lowercase, no padding.
        """
        digest = hashlib.sha256(acme_account_url.encode("utf-8")).digest()[:10]
        return base64.b32encode(digest).decode("ascii").lower().rstrip("=")

    @staticmethod
    def dns_account_name_prefix_for(acme_account_url: str) -> str:
        account_label = Acme.dns_account_label_from_url(acme_account_url)
        return f"_{account_label}.{Acme.ACME_CHALLENGE_LABEL}"
