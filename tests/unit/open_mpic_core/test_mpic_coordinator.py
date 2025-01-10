from itertools import cycle
from unittest.mock import AsyncMock

import pytest

from open_mpic_core.common_domain.check_response import CaaCheckResponse, CaaCheckResponseDetails
from open_mpic_core.common_domain.enum.dcv_validation_method import DcvValidationMethod
from open_mpic_core.common_domain.enum.check_type import CheckType
from open_mpic_core.common_domain.messages.ErrorMessages import ErrorMessages
from open_mpic_core.mpic_coordinator.domain.mpic_orchestration_parameters import MpicRequestOrchestrationParameters
from open_mpic_core.mpic_coordinator.domain.remote_perspective import RemotePerspective
from open_mpic_core.mpic_coordinator.domain.mpic_request_validation_error import MpicRequestValidationError
from open_mpic_core.mpic_coordinator.domain.mpic_response import MpicResponse
from open_mpic_core.mpic_coordinator.mpic_coordinator import MpicCoordinator, MpicCoordinatorConfiguration

from unit.test_util.valid_mpic_request_creator import ValidMpicRequestCreator


# noinspection PyMethodMayBeStatic
class TestMpicCoordinator:
    def create_cohorts_of_randomly_selected_perspectives__should_throw_error_given_requested_count_exceeds_total_perspectives(self):
        mpic_coordinator_config = self.create_mpic_coordinator_configuration()
        target_perspectives = mpic_coordinator_config.target_perspectives
        excessive_count = len(target_perspectives) + 1
        mpic_coordinator = MpicCoordinator(self.create_successful_remote_caa_check_response, mpic_coordinator_config)
        with pytest.raises(ValueError):
            mpic_coordinator.create_cohorts_of_randomly_selected_perspectives(target_perspectives, excessive_count, 'test_target')  # expect error

    def create_cohorts_of_randomly_selected_perspectives__should_return_list_of_cohorts_of_requested_size(self):
        mpic_coordinator_config = self.create_mpic_coordinator_configuration()
        target_perspectives = mpic_coordinator_config.target_perspectives
        cohort_size = len(target_perspectives) // 2
        mpic_coordinator = MpicCoordinator(self.create_successful_remote_caa_check_response, mpic_coordinator_config)
        cohorts = mpic_coordinator.create_cohorts_of_randomly_selected_perspectives(target_perspectives, cohort_size, 'test_target')
        assert len(cohorts) == 2

    @pytest.mark.parametrize('requested_perspective_count, expected_quorum_size', [(4, 3), (5, 4), (6, 4)])
    def determine_required_quorum_count__should_dynamically_set_required_quorum_count_given_no_quorum_specified(
            self, requested_perspective_count, expected_quorum_size):
        command = ValidMpicRequestCreator.create_valid_caa_mpic_request()
        command.orchestration_parameters.quorum_count = None
        mpic_coordinator_config = self.create_mpic_coordinator_configuration()
        mpic_coordinator = MpicCoordinator(self.create_successful_remote_caa_check_response, mpic_coordinator_config)
        required_quorum_count = mpic_coordinator.determine_required_quorum_count(command.orchestration_parameters, requested_perspective_count)
        assert required_quorum_count == expected_quorum_size

    def determine_required_quorum_count__should_use_specified_quorum_count_given_quorum_specified(self):
        command = ValidMpicRequestCreator.create_valid_caa_mpic_request()
        command.orchestration_parameters.quorum_count = 5
        mpic_coordinator_config = self.create_mpic_coordinator_configuration()
        mpic_coordinator = MpicCoordinator(self.create_successful_remote_caa_check_response, mpic_coordinator_config)
        required_quorum_count = mpic_coordinator.determine_required_quorum_count(command.orchestration_parameters, 6)
        assert required_quorum_count == 5

    def collect_async_calls_to_issue__should_have_only_caa_calls_given_caa_check_type(self):
        request = ValidMpicRequestCreator.create_valid_caa_mpic_request()
        mpic_coordinator_config = self.create_mpic_coordinator_configuration()
        target_perspectives = mpic_coordinator_config.target_perspectives
        call_list = MpicCoordinator.collect_async_calls_to_issue(request, target_perspectives)
        assert len(call_list) == 6
        assert set(map(lambda call_result: call_result.check_type, call_list)) == {CheckType.CAA}  # ensure each call is of type 'caa'

    def collect_async_calls_to_issue__should_include_caa_check_parameters_if_present(self):
        request = ValidMpicRequestCreator.create_valid_caa_mpic_request()
        request.caa_check_parameters.caa_domains = ['example.com']
        mpic_coordinator_config = self.create_mpic_coordinator_configuration()
        target_perspectives = mpic_coordinator_config.target_perspectives
        call_list = MpicCoordinator.collect_async_calls_to_issue(request, target_perspectives)
        assert all(call.check_request.caa_check_parameters.caa_domains == ['example.com'] for call in call_list)

    def collect_async_calls_to_issue__should_have_only_dcv_calls_and_include_validation_details_given_dcv_check_type(self):
        request = ValidMpicRequestCreator.create_valid_dcv_mpic_request(DcvValidationMethod.DNS_CHANGE)
        mpic_coordinator_config = self.create_mpic_coordinator_configuration()
        target_perspectives = mpic_coordinator_config.target_perspectives
        call_list = MpicCoordinator.collect_async_calls_to_issue(request, target_perspectives)
        assert len(call_list) == 6
        assert set(map(lambda call_result: call_result.check_type, call_list)) == {CheckType.DCV}  # ensure each call is of type 'dcv'
        assert all(call.check_request.dcv_check_parameters.validation_details.validation_method == DcvValidationMethod.DNS_CHANGE for call in call_list)
        assert all(call.check_request.dcv_check_parameters.validation_details.dns_name_prefix == 'test' for call in call_list)

    async def coordinate_mpic__should_invoke_async_call_remote_perspective_function_with_correct_parameters(self):
        mpic_request = ValidMpicRequestCreator.create_valid_caa_mpic_request()
        mpic_request.orchestration_parameters = MpicRequestOrchestrationParameters(quorum_count=2, perspective_count=2,
                                                                                   max_attempts=2)
        mocked_call_remote_perspective_function = AsyncMock()
        mocked_call_remote_perspective_function.side_effect = TestMpicCoordinator.SideEffectForMockedPayloads(
            self.create_successful_remote_caa_check_response
        )
        mpic_coordinator_config = self.create_mpic_coordinator_configuration()
        mpic_coordinator = MpicCoordinator(mocked_call_remote_perspective_function, mpic_coordinator_config)
        await mpic_coordinator.coordinate_mpic(mpic_request)
        call_args_list = mocked_call_remote_perspective_function.await_args_list
        assert len(call_args_list) == 2
        for call in call_args_list:
            call_args = call.args
            remote_perspective: RemotePerspective = call_args[0]
            assert remote_perspective in mpic_coordinator_config.target_perspectives
            assert call_args[1] == mpic_request.check_type
            check_request = call_args[2]  # was previously a serialized string; now the actual CheckRequest object
            assert check_request.domain_or_ip_target == mpic_request.domain_or_ip_target

    async def coordinate_mpic__should_return_check_success_given_successful_caa_corroboration(self):
        mpic_request = ValidMpicRequestCreator.create_valid_caa_mpic_request()
        mpic_coordinator_config = self.create_mpic_coordinator_configuration()
        mocked_call_remote_perspective_function = AsyncMock()
        mocked_call_remote_perspective_function.side_effect = TestMpicCoordinator.SideEffectForMockedPayloads(
            self.create_successful_remote_caa_check_response
        )
        mpic_coordinator = MpicCoordinator(mocked_call_remote_perspective_function, mpic_coordinator_config)
        mpic_response = await mpic_coordinator.coordinate_mpic(mpic_request)
        assert mpic_response.is_valid is True

    async def coordinate_mpic__should_fully_carry_out_caa_mpic_given_no_parameters_besides_target(self):
        mpic_request = ValidMpicRequestCreator.create_valid_caa_mpic_request()
        mpic_request.orchestration_parameters = None
        mpic_request.caa_check_parameters = None
        mpic_coordinator_config = self.create_mpic_coordinator_configuration()
        mocked_call_remote_perspective_function = AsyncMock()
        mocked_call_remote_perspective_function.side_effect = TestMpicCoordinator.SideEffectForMockedPayloads(
            self.create_successful_remote_caa_check_response
        )
        mpic_coordinator = MpicCoordinator(mocked_call_remote_perspective_function, mpic_coordinator_config)
        mpic_response = await mpic_coordinator.coordinate_mpic(mpic_request)
        assert mpic_response.is_valid is True

    async def coordinate_mpic__should_fully_carry_out_caa_mpic_given_empty_orchestration_parameters(self):
        mpic_request = ValidMpicRequestCreator.create_valid_caa_mpic_request()
        mpic_request.orchestration_parameters = MpicRequestOrchestrationParameters()
        mpic_request.caa_check_parameters = None
        mpic_coordinator_config = self.create_mpic_coordinator_configuration()
        mocked_call_remote_perspective_function = AsyncMock()
        mocked_call_remote_perspective_function.side_effect = TestMpicCoordinator.SideEffectForMockedPayloads(
            self.create_successful_remote_caa_check_response
        )
        mpic_coordinator = MpicCoordinator(mocked_call_remote_perspective_function, mpic_coordinator_config)
        mpic_response = await mpic_coordinator.coordinate_mpic(mpic_request)
        assert mpic_response.is_valid is True

    async def coordinate_mpic__should_fully_carry_out_caa_mpic_given_only_max_attempts_orchestration_parameter(self):
        mpic_request = ValidMpicRequestCreator.create_valid_caa_mpic_request()
        # Reset all fields in orchestration parameters to None
        mpic_request.orchestration_parameters = MpicRequestOrchestrationParameters()
        # Set max_attempts
        mpic_request.orchestration_parameters.max_attempts = 2
        mpic_request.caa_check_parameters = None
        mpic_coordinator_config = self.create_mpic_coordinator_configuration()
        mocked_call_remote_perspective_function = AsyncMock()
        mocked_call_remote_perspective_function.side_effect = TestMpicCoordinator.SideEffectForMockedPayloads(
            self.create_successful_remote_caa_check_response
        )
        mpic_coordinator = MpicCoordinator(mocked_call_remote_perspective_function, mpic_coordinator_config)
        mpic_response = await mpic_coordinator.coordinate_mpic(mpic_request)
        assert mpic_response.is_valid is True

    async def coordinate_mpic__should_retry_corroboration_max_attempts_times_if_corroboration_fails(self):
        mpic_coordinator_config = self.create_mpic_coordinator_configuration()
        mpic_request = ValidMpicRequestCreator.create_valid_caa_mpic_request()
        # there are 3 rirs of 2 perspectives each in the test setup; expect 3 cohorts of 2 perspectives each
        mpic_request.orchestration_parameters = MpicRequestOrchestrationParameters(quorum_count=1, perspective_count=2, max_attempts=3)
        # create mocks that will fail the first two attempts and succeed for the third
        succeed_after_three_attempts = AsyncMock()
        succeed_after_three_attempts.side_effect = self.sequence_of(
            (2, self.create_failing_remote_caa_check_response),
            (2, self.create_failing_remote_response_with_exception),
            (2, self.create_successful_remote_caa_check_response)
        )
        mpic_coordinator = MpicCoordinator(succeed_after_three_attempts, mpic_coordinator_config)
        mpic_response = await mpic_coordinator.coordinate_mpic(mpic_request)
        assert mpic_response.is_valid is True
        assert mpic_response.actual_orchestration_parameters.attempt_count == 3

    async def coordinate_mpic__should_return_check_failure_if_max_attempts_were_reached_without_successful_check(self):
        mpic_request = ValidMpicRequestCreator.create_valid_caa_mpic_request()
        # there are 3 rirs of 2 perspectives each in the test setup; expect 3 cohorts of 2 perspectives each
        mpic_request.orchestration_parameters = MpicRequestOrchestrationParameters(quorum_count=1, perspective_count=2, max_attempts=3)
        mpic_coordinator_config = self.create_mpic_coordinator_configuration()
        mocked_call_remote_perspective_function = AsyncMock()
        mocked_call_remote_perspective_function.side_effect = TestMpicCoordinator.SideEffectForMockedPayloads(
            self.create_failing_remote_caa_check_response
        )
        mpic_coordinator = MpicCoordinator(mocked_call_remote_perspective_function, mpic_coordinator_config)
        mpic_response = await mpic_coordinator.coordinate_mpic(mpic_request)
        assert mpic_response.is_valid is False
        assert mpic_response.actual_orchestration_parameters.attempt_count == 3

    async def coordinate_mpic__should_cycle_through_perspective_cohorts_if_attempts_exceeds_cohort_number(self):
        mpic_coordinator_config = self.create_mpic_coordinator_configuration()

        first_request = ValidMpicRequestCreator.create_valid_caa_mpic_request()
        # there are 3 rirs of 2 perspectives each in the test setup; expect 3 cohorts of 2 perspectives each
        first_request.orchestration_parameters = MpicRequestOrchestrationParameters(quorum_count=1, perspective_count=2, max_attempts=2)
        # "mock" the remote perspective call function that will fail the first cohort and succeed for the second
        # (fail 1a, fail 1b, pass 2a, pass 2b)
        succeed_after_two_attempts = AsyncMock()
        succeed_after_two_attempts.side_effect = self.sequence_of(
            (2, self.create_failing_remote_caa_check_response),
            (2, self.create_successful_remote_caa_check_response)
        )
        mpic_coordinator = MpicCoordinator(succeed_after_two_attempts, mpic_coordinator_config)
        first_response: MpicResponse = await mpic_coordinator.coordinate_mpic(first_request)
        first_cohort = first_response.perspectives
        first_cohort_sorted = sorted(first_cohort, key=lambda check_response: check_response.perspective_code)

        second_request = ValidMpicRequestCreator.create_valid_caa_mpic_request()
        second_request.orchestration_parameters = MpicRequestOrchestrationParameters(quorum_count=1, perspective_count=2, max_attempts=5)
        # "mock" the remote perspective call function that will fail the first four cohorts and succeed for the fifth
        # (loop back, 1-2-3-1-2, i.e., fail 1a+1b, fail 2a+2b, fail 3a+3b, fail 1a+1b again, pass 2a+2b)
        succeed_after_five_attempts = AsyncMock()
        succeed_after_five_attempts.side_effect = self.sequence_of(
            (8, self.create_failing_remote_caa_check_response),
            (2, self.create_successful_remote_caa_check_response)
        )
        mpic_coordinator = MpicCoordinator(succeed_after_five_attempts, mpic_coordinator_config)
        second_response: MpicResponse = await mpic_coordinator.coordinate_mpic(second_request)
        second_cohort = second_response.perspectives
        second_cohort_sorted = sorted(second_cohort, key=lambda check_response: check_response.perspective_code)

        # assert that perspectives in first cohort and in second cohort are the same perspectives
        assert all(first_cohort_sorted[i].perspective_code == second_cohort_sorted[i].perspective_code for i in range(len(first_cohort_sorted)))

    async def coordinate_mpic__should_cap_attempts_at_max_attempts_if_configured(self):
        mpic_coordinator_config = self.create_mpic_coordinator_configuration()
        mpic_coordinator_config.global_max_attempts = 2
        mpic_request = ValidMpicRequestCreator.create_valid_caa_mpic_request()
        # there are 3 rirs of 2 perspectives each in the test setup; expect 3 cohorts of 2 perspectives each
        mpic_request.orchestration_parameters = MpicRequestOrchestrationParameters(quorum_count=1, perspective_count=2,
                                                                                   max_attempts=4)
        mocked_call_remote_perspective_function = AsyncMock()
        mocked_call_remote_perspective_function.side_effect = TestMpicCoordinator.SideEffectForMockedPayloads(
            self.create_failing_remote_caa_check_response
        )
        mpic_coordinator = MpicCoordinator(mocked_call_remote_perspective_function, mpic_coordinator_config)
        mpic_response = await mpic_coordinator.coordinate_mpic(mpic_request)
        assert mpic_response.is_valid is False
        assert mpic_response.actual_orchestration_parameters.attempt_count == 2

    async def coordinate_mpic__should_include_all_previous_attempt_results_if_there_were_retries(self):
        mpic_coordinator_config = self.create_mpic_coordinator_configuration()
        mpic_request = ValidMpicRequestCreator.create_valid_caa_mpic_request()
        mpic_request.orchestration_parameters = MpicRequestOrchestrationParameters(quorum_count=1, perspective_count=2, max_attempts=3)
        # "mock" the remote perspective call function that will fail the first two attempts and succeed for the third
        # (fail 1a, fail 1b, fail 2a, fail 2b, pass 3a, pass 3b)
        succeed_after_three_attempts = AsyncMock()
        succeed_after_three_attempts.side_effect = self.sequence_of(
            (4, self.create_failing_remote_caa_check_response),
            (2, self.create_successful_remote_caa_check_response)
        )
        mpic_coordinator = MpicCoordinator(succeed_after_three_attempts, mpic_coordinator_config)
        mpic_response = await mpic_coordinator.coordinate_mpic(mpic_request)
        assert mpic_response.is_valid is True
        assert mpic_response.actual_orchestration_parameters.attempt_count == 3
        previous_attempts = mpic_response.previous_attempt_results
        assert len(previous_attempts) == 2
        for perspective_result_list in previous_attempts:
            assert len(perspective_result_list) == 2
            assert all(not perspective.check_passed for perspective in perspective_result_list)

    @pytest.mark.parametrize('check_type', [CheckType.CAA, CheckType.DCV])
    async def coordinate_mpic__should_return_check_failure_message_given_remote_perspective_failure(self, check_type):
        mpic_request = None
        match check_type:
            case CheckType.CAA:
                mpic_request = ValidMpicRequestCreator.create_valid_caa_mpic_request()
            case CheckType.DCV:
                mpic_request = ValidMpicRequestCreator.create_valid_dcv_mpic_request()
        mpic_coordinator_config = self.create_mpic_coordinator_configuration()

        mocked_call_remote_perspective_function = AsyncMock()
        mocked_call_remote_perspective_function.side_effect = TestMpicCoordinator.SideEffectForMockedPayloads(
            self.create_failing_remote_response_with_exception
        )
        mpic_coordinator = MpicCoordinator(mocked_call_remote_perspective_function, mpic_coordinator_config)

        mpic_response = await mpic_coordinator.coordinate_mpic(mpic_request)
        assert mpic_response.is_valid is False
        for perspective in mpic_response.perspectives:
            assert perspective.check_passed is False
            assert perspective.errors[0].error_type == ErrorMessages.COORDINATOR_COMMUNICATION_ERROR.key

    async def coordinate_mpic__should_raise_exception_given_logically_invalid_mpic_request(self):
        mpic_request = ValidMpicRequestCreator.create_valid_caa_mpic_request()
        mpic_request.orchestration_parameters = MpicRequestOrchestrationParameters(quorum_count=15, perspective_count=5,
                                                                                   max_attempts=1)
        # noinspection PyTypeChecker
        mpic_request.domain_or_ip_target = None
        mpic_coordinator_config = self.create_mpic_coordinator_configuration()
        mocked_call_remote_perspective_function = AsyncMock()
        mocked_call_remote_perspective_function.side_effect = TestMpicCoordinator.SideEffectForMockedPayloads(
            self.create_successful_remote_caa_check_response
        )
        mpic_coordinator = MpicCoordinator(mocked_call_remote_perspective_function, mpic_coordinator_config)
        with pytest.raises(MpicRequestValidationError):
            await mpic_coordinator.coordinate_mpic(mpic_request)

    async def coordinate_mpic__should_return_trace_identifier_if_included_in_request(self):
        mpic_request = ValidMpicRequestCreator.create_valid_caa_mpic_request()
        mpic_request.trace_identifier = 'test_trace_identifier'
        mpic_coordinator_config = self.create_mpic_coordinator_configuration()
        mocked_call_remote_perspective_function = AsyncMock()
        mocked_call_remote_perspective_function.side_effect = TestMpicCoordinator.SideEffectForMockedPayloads(
            self.create_successful_remote_caa_check_response
        )
        mpic_coordinator = MpicCoordinator(mocked_call_remote_perspective_function, mpic_coordinator_config)
        mpic_response = await mpic_coordinator.coordinate_mpic(mpic_request)
        assert mpic_response.trace_identifier == 'test_trace_identifier'

    async def coordinate_mpic__should_return_domain_or_ip_target_if_included_in_request(self):
        mpic_request = ValidMpicRequestCreator.create_valid_caa_mpic_request()
        mpic_request.domain_or_ip_target = 'test_domain_or_ip_target'
        mpic_coordinator_config = self.create_mpic_coordinator_configuration()
        mocked_call_remote_perspective_function = AsyncMock()
        mocked_call_remote_perspective_function.side_effect = TestMpicCoordinator.SideEffectForMockedPayloads(
            self.create_successful_remote_caa_check_response
        )
        mpic_coordinator = MpicCoordinator(mocked_call_remote_perspective_function, mpic_coordinator_config)
        mpic_response = await mpic_coordinator.coordinate_mpic(mpic_request)
        assert mpic_response.domain_or_ip_target == 'test_domain_or_ip_target'

    def constructor__should_treat_max_attempts_as_optional_and_default_to_none(self):
        mpic_coordinator_configuration = self.create_mpic_coordinator_configuration()
        mpic_coordinator = MpicCoordinator(self.create_successful_remote_caa_check_response, mpic_coordinator_configuration)
        assert mpic_coordinator.global_max_attempts is None

    def constructor__should_set_configuration_and_remote_perspective_call_function(self):
        mpic_coordinator_configuration = self.create_mpic_coordinator_configuration()

        def call_remote_perspective():
            return 'this_is_a_dummy_response'

        mpic_coordinator = MpicCoordinator(call_remote_perspective, mpic_coordinator_configuration)
        assert mpic_coordinator.global_max_attempts == mpic_coordinator_configuration.global_max_attempts
        assert mpic_coordinator.target_perspectives == mpic_coordinator_configuration.target_perspectives
        assert mpic_coordinator.default_perspective_count == mpic_coordinator_configuration.default_perspective_count
        assert mpic_coordinator.hash_secret == mpic_coordinator_configuration.hash_secret
        assert mpic_coordinator.call_remote_perspective_function == call_remote_perspective

    @staticmethod
    def create_mpic_coordinator_configuration() -> MpicCoordinatorConfiguration:
        target_perspective_codes = ['us-east-1', 'us-west-1',
                                    'eu-west-2', 'eu-central-2',
                                    'ap-northeast-1', 'ap-south-2']
        all_perspectives_by_code = TestMpicCoordinator.create_all_perspectives_by_code()
        target_perspectives = [all_perspectives_by_code[code] for code in target_perspective_codes]
        default_perspective_count = 3
        global_max_attempts = None
        hash_secret = 'test_secret'
        mpic_coordinator_configuration = MpicCoordinatorConfiguration(
            target_perspectives,
            default_perspective_count,
            global_max_attempts,
            hash_secret)
        return mpic_coordinator_configuration

    @staticmethod
    def create_all_perspectives_by_code() -> dict[str, RemotePerspective]:
        perspectives = [
            RemotePerspective(rir='arin', code='us-east-1'),
            RemotePerspective(rir='arin', code='us-west-1'),
            RemotePerspective(rir='ripe', code='eu-west-2'),
            RemotePerspective(rir='ripe', code='eu-central-2'),
            RemotePerspective(rir='apnic', code='ap-northeast-1'),
            RemotePerspective(rir='apnic', code='ap-south-2')
        ]
        return {perspective.code: perspective for perspective in perspectives}

    # This also can be used for call_remote_perspective
    # noinspection PyUnusedLocal
    def create_successful_remote_caa_check_response(self, perspective: RemotePerspective, check_type: CheckType,
                                                    check_request_serialized: str):
        return CaaCheckResponse(perspective_code=perspective.code, check_passed=True,
                                details=CaaCheckResponseDetails(caa_record_present=False))

    # noinspection PyUnusedLocal
    def create_failing_remote_caa_check_response(self, perspective: RemotePerspective, check_type: CheckType,
                                                 check_request_serialized: str):
        return CaaCheckResponse(perspective_code=perspective.code, check_passed=False,
                                details=CaaCheckResponseDetails(caa_record_present=True))

    # noinspection PyUnusedLocal
    def create_failing_remote_response_with_exception(self, perspective: RemotePerspective, check_type: CheckType,
                                                      check_request_serialized: str):
        raise Exception("Something went wrong.")

    # helper function to create a sequence of functions to be called in order (for mocking)
    # used to simulate multiple attempts at remote perspective calls where some fail and some succeed
    def sequence_of(self, *count_per_function: tuple[int, callable]):
        sequence = []
        for count, fn in count_per_function:
            sequence.extend([fn] * count)
        return TestMpicCoordinator.SideEffectForMockedPayloads(*sequence)

    class SideEffectForMockedPayloads:
        # This cycles, so if we just need to return 'success' every time, we only need to pass the success function
        # once. Otherwise, we need to pass the success function as many times as we want it to be called and then
        # whatever needs to follow -- failures, errors.
        def __init__(self, *functions_to_call):
            self.functions_to_call = cycle(functions_to_call)

        def __call__(self, *args, **kwargs):
            function_to_call = next(self.functions_to_call)
            return function_to_call(*args, **kwargs)


if __name__ == '__main__':
    pytest.main()
