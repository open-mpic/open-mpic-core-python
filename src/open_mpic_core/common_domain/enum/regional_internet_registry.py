from enum import StrEnum


class RegionalInternetRegistry(StrEnum):
    ARIN = "ARIN"
    RIPE_NCC = "RIPE NCC"
    APNIC = "APNIC"
    LACNIC = "LACNIC"
    AFRINIC = "AFRINIC"

    @classmethod
    def _missing_(cls, value: str) -> str | None:
        value = value.upper()
        for member in cls:
            if member.upper() == value:
                return member
        return None
