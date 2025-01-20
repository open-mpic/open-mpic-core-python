import pytest

from open_mpic_core.common_util.domain_encoder import DomainEncoder


class TestDomainEncoder:
    @pytest.mark.parametrize("input_domain, expected_output", [
        ("café.example.com", "xn--caf-dma.example.com"),
        ("bücher.example.de", "xn--bcher-kva.example.de"),
        ("свічка.example.com", "xn--80ady0a5a8f.example.com"),
        ("127.0.0.1", "127.0.0.1"),
        ("example.com", "example.com"),
        ("*.example.com", "*.example.com"),
        ("*.café.example.com", "*.xn--caf-dma.example.com"),
    ])
    def prepare_domain_for_lookup__should_convert_nonascii_domain_to_punycode(self, input_domain, expected_output):
        result = DomainEncoder.prepare_target_for_lookup(input_domain)
        assert result == expected_output
