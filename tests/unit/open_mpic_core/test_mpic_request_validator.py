import sys
import pytest

from open_mpic_core.common_domain.enum.dcv_validation_method import DcvValidationMethod
from open_mpic_core.mpic_coordinator.domain.remote_perspective import RemotePerspective
from open_mpic_core.mpic_coordinator.messages.mpic_request_validation_messages import MpicRequestValidationMessages
from open_mpic_core.mpic_coordinator.mpic_request_validator import MpicRequestValidator
from unit.test_util.valid_mpic_request_creator import ValidMpicRequestCreator


# noinspection PyMethodMayBeStatic
class TestMpicRequestValidator:
    @classmethod
    def setup_class(cls):
        cls.known_perspectives = [
            RemotePerspective(rir='rir1', code='p1'), RemotePerspective(rir='rir1', code='p2'),
            RemotePerspective(rir='rir1', code='p3'), RemotePerspective(rir='rir1', code='p4'),
            RemotePerspective(rir='rir2', code='p5'), RemotePerspective(rir='rir2', code='p6'),
            RemotePerspective(rir='rir2', code='p7'), RemotePerspective(rir='rir2', code='p8'),
            RemotePerspective(rir='rir3', code='p9'), RemotePerspective(rir='rir3', code='p10')
        ]

    def is_request_valid__should_return_true_and_empty_list_given_valid_caa_check_request_with_perspective_count(self):
        request = ValidMpicRequestCreator.create_valid_caa_mpic_request()
        is_request_valid, validation_issues = MpicRequestValidator.is_request_valid(request, self.known_perspectives)
        assert is_request_valid is True
        assert len(validation_issues) == 0

    def is_request_valid__should_return_true_given_valid_caa_check_without_orchestration_parameters_or_caa_check_details(self):
        request = ValidMpicRequestCreator.create_valid_caa_mpic_request()
        request.orchestration_parameters = None
        request.caa_check_parameters = None
        is_request_valid, validation_issues = MpicRequestValidator.is_request_valid(request, self.known_perspectives)
        assert is_request_valid is True
        assert len(validation_issues) == 0

    @pytest.mark.parametrize('validation_method', [DcvValidationMethod.DNS_CHANGE, DcvValidationMethod.WEBSITE_CHANGE_V2])
    def is_request_valid__should_return_true_given_valid_dcv_check_request(self, validation_method):
        request = ValidMpicRequestCreator.create_valid_dcv_mpic_request(validation_method)
        is_request_valid, validation_issues = MpicRequestValidator.is_request_valid(request, self.known_perspectives)
        assert is_request_valid is True
        assert len(validation_issues) == 0

    @pytest.mark.parametrize('perspective_count', [1, 0, -1, 'abc', sys.maxsize+1])
    def is_request_valid__should_return_false_and_message_given_invalid_perspective_count(self, perspective_count):
        request = ValidMpicRequestCreator.create_valid_caa_mpic_request()
        request.orchestration_parameters.perspective_count = perspective_count
        is_request_valid, validation_issues = MpicRequestValidator.is_request_valid(request, self.known_perspectives)
        assert is_request_valid is False
        assert MpicRequestValidationMessages.INVALID_PERSPECTIVE_COUNT.key in [issue.issue_type for issue in validation_issues]
        invalid_perspective_count_issue = next(issue for issue in validation_issues if issue.issue_type == MpicRequestValidationMessages.INVALID_PERSPECTIVE_COUNT.key)
        assert str(perspective_count) in invalid_perspective_count_issue.message

    # TODO should there be a more permissive validation (in diagnostic mode?) for quorum count?
    @pytest.mark.parametrize('quorum_count', [1, -1, 0, 10, 'abc', sys.maxsize+1])
    def is_request_valid__should_return_false_and_message_given_invalid_quorum_count(self, quorum_count):
        request = ValidMpicRequestCreator.create_valid_caa_mpic_request()
        request.orchestration_parameters.quorum_count = quorum_count
        is_request_valid, validation_issues = MpicRequestValidator.is_request_valid(request, self.known_perspectives)
        assert is_request_valid is False
        assert MpicRequestValidationMessages.INVALID_QUORUM_COUNT.key in [issue.issue_type for issue in validation_issues]
        invalid_quorum_count_issue = next(issue for issue in validation_issues if issue.issue_type == MpicRequestValidationMessages.INVALID_QUORUM_COUNT.key)
        assert str(quorum_count) in invalid_quorum_count_issue.message


if __name__ == '__main__':
    pytest.main()
