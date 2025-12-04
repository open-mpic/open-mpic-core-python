from open_mpic_core import CheckType, MpicRequest, DcvValidationMethod
from open_mpic_core import MpicRequestValidationMessages, MpicRequestValidationIssue


class MpicRequestValidator:
    @staticmethod
    # returns a list of validation issues found in the request; if empty, request is (probably) valid
    # TODO should we create a flag to validate values separately from structure?
    def is_request_valid(mpic_request: MpicRequest, known_perspectives) -> (bool, list):
        request_validation_issues = []

        should_validate_quorum_count = False
        requested_perspective_count = 0
        if mpic_request.orchestration_parameters is not None:
            if mpic_request.orchestration_parameters.perspective_count is not None:
                requested_perspective_count = mpic_request.orchestration_parameters.perspective_count
                if MpicRequestValidator.is_requested_perspective_count_valid(
                    requested_perspective_count, known_perspectives
                ):
                    should_validate_quorum_count = True
                else:
                    request_validation_issues.append(
                        MpicRequestValidationIssue(
                            MpicRequestValidationMessages.INVALID_PERSPECTIVE_COUNT, requested_perspective_count
                        )
                    )
            if should_validate_quorum_count and mpic_request.orchestration_parameters.quorum_count is not None:
                quorum_count = mpic_request.orchestration_parameters.quorum_count
                MpicRequestValidator.validate_quorum_count(
                    requested_perspective_count, quorum_count, request_validation_issues
                )

        if mpic_request.check_type == CheckType.DCV:
            check_parameters = mpic_request.dcv_check_parameters
            if (
                check_parameters.validation_method == DcvValidationMethod.WEBSITE_CHANGE
                and check_parameters.challenge_value == ""
                and (check_parameters.match_regex is None or check_parameters.match_regex == "")
            ):
                request_validation_issues.append(
                    MpicRequestValidationIssue(
                        MpicRequestValidationMessages.EMPTY_CHALLENGE_VALUE,
                        check_parameters.challenge_value,
                    )
                )

        # returns true if no validation issues found, false otherwise; includes list of validation issues found
        return len(request_validation_issues) == 0, request_validation_issues

    @staticmethod
    def is_requested_perspective_count_valid(requested_perspective_count, target_perspectives) -> bool:
        # check if requested_perspective_count is an integer, at least 2, and at most the number of known_perspectives
        return isinstance(requested_perspective_count, int) and 2 <= requested_perspective_count <= len(
            target_perspectives
        )

    @staticmethod
    def is_requested_cohort_for_single_attempt_valid(cohort_for_single_attempt, number_of_cohorts) -> bool:
        # check if cohort_for_single_attempt is an integer and is within the number of available cohorts
        return isinstance(cohort_for_single_attempt, int) and 1 <= cohort_for_single_attempt <= number_of_cohorts

    @staticmethod
    def validate_quorum_count(requested_perspective_count, quorum_count, request_validation_issues) -> None:
        # quorum_count can be no less than perspectives-1 if perspectives <= 5
        # quorum_count can be no less than perspectives-2 if perspectives > 5
        quorum_is_valid = isinstance(quorum_count, int) and (
            (requested_perspective_count - 1 <= quorum_count <= requested_perspective_count <= 5)
            or (4 <= requested_perspective_count - 2 <= quorum_count <= requested_perspective_count)
        )
        if not quorum_is_valid:
            request_validation_issues.append(
                MpicRequestValidationIssue(MpicRequestValidationMessages.INVALID_QUORUM_COUNT, quorum_count)
            )
