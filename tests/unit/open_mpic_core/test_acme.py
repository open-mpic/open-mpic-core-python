import pytest

from open_mpic_core import Acme, DcvAcmeDnsAccount01ValidationParameters


class TestAcme:
    def dns_account_label_from_url__should_match_draft_test_vector(self):
        account_url = "https://example.com/acme/acct/ExampleAccount"
        assert Acme.dns_account_label_from_url(account_url) == "ujmmovf2vn55tgye"

    @pytest.mark.parametrize(
        "account_url",
        [
            "https://ca.example/acme/acct/123",
            "http://authority.example/acme/acct/foo",
        ],
    )
    def dns_account_label_from_url__should_return_lowercase_base32_without_padding(self, account_url):
        label = Acme.dns_account_label_from_url(account_url)
        assert label == label.lower()
        assert "=" not in label
        assert all(char in "abcdefghijklmnopqrstuvwxyz234567" for char in label)

    def dns_account_name_prefix_for__should_build_acme_challenge_prefix(self):
        account_url = "https://example.com/acme/acct/ExampleAccount"
        assert Acme.dns_account_name_prefix_for(account_url) == "_ujmmovf2vn55tgye._acme-challenge"


class TestDcvAcmeDnsAccount01ValidationParameters:
    def dcv_acme_dns_account_01_parameters__should_derive_dns_name_prefix_from_account_url(self):
        parameters = DcvAcmeDnsAccount01ValidationParameters(
            acme_account_url="https://example.com/acme/acct/ExampleAccount",
            key_authorization_hash="abc123",
        )
        assert parameters.dns_name_prefix == "_ujmmovf2vn55tgye._acme-challenge"

    def dcv_acme_dns_account_01_parameters__should_reject_invalid_account_url(self):
        with pytest.raises(ValueError, match="acme_account_url must be a valid URI"):
            DcvAcmeDnsAccount01ValidationParameters(
                acme_account_url="not-a-valid-uri",
                key_authorization_hash="abc123",
            )
