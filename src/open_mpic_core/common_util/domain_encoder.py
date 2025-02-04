import ipaddress
import idna


class DomainEncoder:
    @staticmethod
    def prepare_target_for_lookup(domain_or_ip_target) -> str:
        try:
            # First check if it's an IP address
            ipaddress.ip_address(domain_or_ip_target)
            return domain_or_ip_target
        except ValueError:
            # Not an IP address, process as domain
            pass

        # Convert to IDNA/Punycode
        try:
            is_wildcard = domain_or_ip_target.startswith("*.")
            if is_wildcard:
                domain_or_ip_target = domain_or_ip_target[2:]  # Remove *. prefix

            encoded_domain = idna.encode(domain_or_ip_target, uts46=True).decode("ascii")
            return encoded_domain
        except idna.IDNAError as e:
            raise ValueError(f"Invalid domain name: {str(e)}")
