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
        )