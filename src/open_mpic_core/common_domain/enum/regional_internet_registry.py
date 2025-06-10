from enum import StrEnum


class RegionalInternetRegistry(StrEnum):
    ARIN = "ARIN"
    RIPE_NCC = "RIPE NCC"
    APNIC = "APNIC"
    LACNIC = "LACNIC"
    AFRINIC = "AFRINIC"

    @classmethod
    def _missing_(cls, value: str) -> str | None:
        """
        This method is called when a value is not found in the enum. It basically makes enum lookups case-insensitive.
        :param value: the string value to look up.
        :return: The RegionalInternetRegistry member if found, otherwise None.
        """
        value = value.upper()
        for member in cls:
            if member.upper() == value:
                return member
        return None
