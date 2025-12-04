import pytest

from open_mpic_core import DomainEncoder


class TestDomainEncoder:

    @staticmethod
    @pytest.mark.parametrize(
        "input_domain, expected_output",
        [
            ("café.example.com", "xn--caf-dma.example.com"),
            ("bücher.example.de", "xn--bcher-kva.example.de"),
            ("127.0.0.1", "127.0.0.1"),
            ("example.com", "example.com"),
            ("subdomain.café.example.com", "subdomain.xn--caf-dma.example.com"),
        ],
    )
    def prepare_domain_for_lookup__should_convert_nonascii_domain_to_punycode(input_domain, expected_output):
        result = DomainEncoder.prepare_target_for_lookup(input_domain)
        assert result == expected_output

    @staticmethod
    @pytest.mark.parametrize(
        "input_domain, expected_output",
        [
            ("*.example.com", "example.com"),  # ascii
            ("*.café.example.com", "xn--caf-dma.example.com"),  # not encoded
            ("*.xn--yaztura-tfb.com", "xn--yaztura-tfb.com"),  # already encoded
        ],
    )
    def prepare_domain_for_lookup__should_remove_leading_asterisk_from_wildcard_domain(input_domain, expected_output):
        result = DomainEncoder.prepare_target_for_lookup(input_domain)
        assert result == expected_output

    @staticmethod
    @pytest.mark.parametrize(
        "input_domain, expected_output",
        [
            ("xn--caf-dma.example.com", "xn--caf-dma.example.com"),  # café.example.com idna2008
            ("*.xn--yaztura-tfb.com", "xn--yaztura-tfb.com"),
            ("xn--nxasmm1c.com", "xn--nxasmm1c.com"),  # "βόλος.com" idna2008
            ("xn--ls8h.la", "xn--ls8h.la"),  # poop emoji idna2003
            ("xn--4ca.com", "xn--4ca.com"),  # "√.com" idna2003
        ],
    )
    def prepare_domain_for_lookup__should_allow_already_encoded_domain(input_domain, expected_output):
        result = DomainEncoder.prepare_target_for_lookup(input_domain)
        assert result == expected_output

    @staticmethod
    @pytest.mark.parametrize(
        "input_domain, expected_output",
        [
            ("sub.xn--caf-dma.example.com", "sub.xn--caf-dma.example.com"),
            ("sub.xn--4ca.com", "sub.xn--4ca.com"),  # "√.com" idna2003
            ("sub.xn--ls8h.la", "sub.xn--ls8h.la"),  # poop emoji idna2003
        ],
    )
    def prepare_domain_for_lookup__should_detect_punycode_in_inner_labels(input_domain, expected_output):
        result = DomainEncoder.prepare_target_for_lookup(input_domain)
        assert result == expected_output

    @staticmethod
    @pytest.mark.parametrize(
        "input_domain",
        [
            "*example.com",
            "exa mple.com",
            "exam!ple.com",
            "xn--café.com",  # invalid (punycode prefix on non-ascii string)
        ],
    )
    def prepare_domain_for_lookup__should_raise_value_error_given_malformed_domain(input_domain):
        with pytest.raises(ValueError):
            DomainEncoder.prepare_target_for_lookup(input_domain)
