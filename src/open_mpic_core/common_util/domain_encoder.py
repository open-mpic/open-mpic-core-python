import ipaddress

import dns.name
import idna
from dns.name import IDNAException


class DomainEncoder:
    @staticmethod
    def prepare_target_for_lookup(domain_or_ip_target) -> str:
        # Handle bracketed IPv6 addresses (e.g., [2606:4700:4700::1111])
        if domain_or_ip_target.startswith("[") and domain_or_ip_target.endswith("]"):
            inner = domain_or_ip_target[1:-1]
            try:
                ipaddress.ip_address(inner)
                return inner  # Return the IPv6 address without brackets
            except ValueError:
                pass  # Not a valid IP, will be handled below

        try:
            # First check if it's an IP address
            ipaddress.ip_address(domain_or_ip_target)
            return domain_or_ip_target
        except ValueError:
            # Not an IP address, process as domain
            pass

        # Convert to IDNA/Punycode
        is_wildcard = domain_or_ip_target.startswith("*.")
        if is_wildcard:
            domain_or_ip_target = domain_or_ip_target[2:]  # Remove *. prefix

        prepared_domain = domain_or_ip_target
        is_already_encoded = False

        for label_text in domain_or_ip_target.split("."):
            # check if any label is punycode encoded
            if label_text.startswith("xn--"):
                try:
                    label_bytes = label_text.encode("ascii")
                    try:
                        dns.name.IDNA_2008_Strict.decode(label_bytes)
                    except IDNAException:
                        try:
                            dns.name.IDNA_2003_Strict.decode(label_bytes)
                        except IDNAException as e2:
                            raise ValueError(f"Invalid domain name: {str(e2)}")
                except UnicodeEncodeError:
                    raise ValueError(f"Invalid domain name: Label '{label_text}' is not valid ASCII.")
                # if we made it here then we had a valid punycode label
                is_already_encoded = True

        if not is_already_encoded:
            try:
                prepared_domain = idna.encode(domain_or_ip_target, uts46=True).decode("ascii")
            except idna.IDNAError as e:
                raise ValueError(f"Invalid domain name: {str(e)}")

        return prepared_domain
