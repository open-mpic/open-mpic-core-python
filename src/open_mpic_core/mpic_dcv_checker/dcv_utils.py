from open_mpic_core.__about__ import __api_version__
from open_mpic_core import DcvValidationMethod, DcvCheckResponse, DcvCheckResponseDetailsBuilder


class DcvUtils:
    @staticmethod
    def create_empty_check_response(validation_method: DcvValidationMethod) -> DcvCheckResponse:
        return DcvCheckResponse(
            check_completed=False,
            check_passed=False,
            timestamp_ns=None,
            errors=None,
            details=DcvCheckResponseDetailsBuilder.build_response_details(validation_method),
            api_version=__api_version__,
        )
