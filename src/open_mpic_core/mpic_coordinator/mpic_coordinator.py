import asyncio
import json
from itertools import cycle

from pprint import pformat
import time
import hashlib

from open_mpic_core import CaaCheckResponse, DcvCheckResponse, CaaCheckResponseDetails
from open_mpic_core import MpicRequest, MpicResponse, PerspectiveResponse
from open_mpic_core import CaaCheckRequest, DcvCheckRequest
from open_mpic_core import DcvCheckResponseDetailsBuilder
from open_mpic_core import MpicRequestValidationException
from open_mpic_core import MpicValidationError, ErrorMessages
from open_mpic_core import CheckType
from open_mpic_core import CohortCreator
from open_mpic_core import RemoteCheckException
from open_mpic_core import RemoteCheckCallConfiguration
from open_mpic_core import RemotePerspective
from open_mpic_core import MpicRequestValidationMessages
from open_mpic_core import MpicRequestValidator
from open_mpic_core import MpicResponseBuilder
from open_mpic_core import get_logger

logger = get_logger(__name__)


class MpicCoordinatorConfiguration:
    def __init__(self, target_perspectives, default_perspective_count, global_max_attempts, hash_secret):
        self.target_perspectives = target_perspectives
        self.default_perspective_count = default_perspective_count
        self.global_max_attempts = global_max_attempts
        self.hash_secret = hash_secret


class MpicCoordinator:
    def __init__(
        self,
        call_remote_perspective_function,
        mpic_coordinator_configuration: MpicCoordinatorConfiguration,
        log_level: int = None,
    ):
        """
        :param call_remote_perspective_function: a "dumb" transport for serialized data to a remote perspective and
               a serialized response from the remote perspective. MPIC Coordinator is tasked with ensuring the data
               from this function is sane and handling the serialization/deserialization of the data. This function
               may raise an exception if something goes wrong.
        :param mpic_coordinator_configuration: environment-specific configuration for the coordinator.
        :param log_level: optional parameter for logging. For now really just used for TRACE logging.
        """
        self.target_perspectives = mpic_coordinator_configuration.target_perspectives
        self.default_perspective_count = mpic_coordinator_configuration.default_perspective_count
        self.global_max_attempts = mpic_coordinator_configuration.global_max_attempts
        self.hash_secret = mpic_coordinator_configuration.hash_secret
        self.call_remote_perspective_function = call_remote_perspective_function

        self.logger = logger.getChild(self.__class__.__name__)
        if log_level is not None:
            self.logger.setLevel(log_level)

    async def coordinate_mpic(self, mpic_request: MpicRequest) -> MpicResponse:
        # noinspection PyUnresolvedReferences
        self.logger.trace(f"Coordinating MPIC request with trace ID {mpic_request.trace_identifier}")

        self._raise_exception_on_invalid_request(mpic_request)

        orchestration_parameters = mpic_request.orchestration_parameters

        perspective_count = self.default_perspective_count
        if orchestration_parameters is not None and orchestration_parameters.perspective_count is not None:
            perspective_count = orchestration_parameters.perspective_count

        perspective_cohorts = self.shuffle_and_group_perspectives(
            self.target_perspectives, perspective_count, mpic_request.domain_or_ip_target
        )

        quorum_count = self.determine_required_quorum_count(orchestration_parameters, perspective_count)

        if orchestration_parameters is not None and orchestration_parameters.max_attempts is not None:
            max_attempts = orchestration_parameters.max_attempts
            if self.global_max_attempts is not None and max_attempts > self.global_max_attempts:
                max_attempts = self.global_max_attempts
        else:
            max_attempts = 1
        attempts = 1
        previous_attempt_results = None
        cohort_cycle = cycle(perspective_cohorts)
        while attempts <= max_attempts:
            perspectives_to_use = next(cohort_cycle)

            # Collect async calls to invoke for each perspective.
            async_calls_to_issue = MpicCoordinator.collect_checker_calls_to_issue(mpic_request, perspectives_to_use)

            perspective_responses = await self.call_checkers_and_collect_responses(
                mpic_request, perspectives_to_use, async_calls_to_issue
            )

            check_passed_per_perspective = {
                response.perspective_code: response.check_response.check_passed for response in perspective_responses
            }

            valid_perspective_count = sum(check_passed_per_perspective.values())
            is_valid_result = valid_perspective_count >= quorum_count

            # noinspection PyUnresolvedReferences
            self.logger.trace(f"Perspectives used in attempt: \n%s", pformat(perspectives_to_use))
            # noinspection PyUnresolvedReferences
            self.logger.trace(f"Check passed per perspective: \n%s", pformat(check_passed_per_perspective))

            # if cohort size is larger than 2, then at least two RIRs must be represented in the SUCCESSFUL perspectives
            if len(perspectives_to_use) > 2:
                valid_perspectives = [
                    perspective for perspective in perspectives_to_use if check_passed_per_perspective[perspective.code]
                ]
                rir_count = len(set(perspective.rir for perspective in valid_perspectives))
                is_valid_result = rir_count >= 2 and is_valid_result

            if is_valid_result or attempts == max_attempts:
                response = MpicResponseBuilder.build_response(
                    mpic_request,
                    perspective_count,
                    quorum_count,
                    attempts,
                    perspective_responses,
                    is_valid_result,
                    previous_attempt_results,
                )

                # noinspection PyUnresolvedReferences
                self.logger.trace(f"Completed MPIC request with trace ID {mpic_request.trace_identifier}")
                return response
            else:
                if previous_attempt_results is None:
                    previous_attempt_results = []
                previous_attempt_results.append(perspective_responses)
                attempts += 1

    def _raise_exception_on_invalid_request(self, mpic_request):
        is_request_valid, validation_issues = MpicRequestValidator.is_request_valid(
            mpic_request, self.target_perspectives
        )
        if not is_request_valid:
            error = MpicRequestValidationException(MpicRequestValidationMessages.REQUEST_VALIDATION_FAILED.key)
            validation_issues_as_string = json.dumps([vars(issue) for issue in validation_issues])
            error.add_note(validation_issues_as_string)
            raise error

    # Returns randomized grouping(s) of perspectives with a goal of maximum RIR diversity.
    # If more than 2 perspectives are needed (count), it will enforce a minimum of 2 RIRs per cohort.
    def shuffle_and_group_perspectives(self, target_perspectives, cohort_size, domain_or_ip_target):
        if cohort_size > len(target_perspectives):
            raise ValueError(
                f"Count ({cohort_size}) must be <= the number of available perspectives ({len(target_perspectives)})"
            )

        random_seed = hashlib.sha256((self.hash_secret + domain_or_ip_target.lower()).encode("utf-8")).digest()
        perspectives_per_rir = CohortCreator.shuffle_available_perspectives_per_rir(target_perspectives, random_seed)
        cohorts = CohortCreator.create_perspective_cohorts(perspectives_per_rir, cohort_size)
        return cohorts

    # Determines the minimum required quorum size if none is specified in the request.
    @staticmethod
    def determine_required_quorum_count(orchestration_parameters, perspective_count):
        if orchestration_parameters is not None and orchestration_parameters.quorum_count is not None:
            required_quorum_count = orchestration_parameters.quorum_count
        else:
            required_quorum_count = perspective_count - 1 if perspective_count <= 5 else perspective_count - 2
        return required_quorum_count

    # Configures the async remote perspective calls to issue for the check request.
    @staticmethod
    def collect_checker_calls_to_issue(
        mpic_request, perspectives_to_use: list[RemotePerspective]
    ) -> list[RemoteCheckCallConfiguration]:
        domain_or_ip_target = mpic_request.domain_or_ip_target
        check_type = mpic_request.check_type
        async_calls_to_issue = []

        # check if mpic_request is an instance of MpicCaaRequest or MpicDcvRequest
        if check_type == CheckType.CAA:
            check_parameters = CaaCheckRequest(
                domain_or_ip_target=domain_or_ip_target,
                caa_check_parameters=mpic_request.caa_check_parameters,
                trace_identifier=mpic_request.trace_identifier,
            )
        else:
            check_parameters = DcvCheckRequest(
                domain_or_ip_target=domain_or_ip_target,
                dcv_check_parameters=mpic_request.dcv_check_parameters,
                trace_identifier=mpic_request.trace_identifier,
            )

        for perspective in perspectives_to_use:
            call_config = RemoteCheckCallConfiguration(check_type, perspective, check_parameters)
            async_calls_to_issue.append(call_config)

        return async_calls_to_issue

    async def call_remote_perspective(
        self, call_remote_perspective_function, call_config: RemoteCheckCallConfiguration
    ) -> PerspectiveResponse:
        """
        Async wrapper around the perspective call function.
        This assumes the wrapper will provide an async version of call_remote_perspective_function,
        or that we'll wrap the sync function using asyncio.to_thread() if needed.
        """
        try:
            # noinspection PyUnresolvedReferences
            async with self.logger.trace_timing(f"MPIC round-trip with perspective {call_config.perspective.code}"):
                response = await call_remote_perspective_function(
                    call_config.perspective, call_config.check_type, call_config.check_request
                )
        except Exception as exc:
            error_message = str(exc) if str(exc) else exc.__class__.__name__
            raise RemoteCheckException(
                f"Check failed for perspective {call_config.perspective.code}: {error_message}",
                call_config=call_config,
            ) from exc
        return PerspectiveResponse(perspective_code=call_config.perspective.code, check_response=response)

    @staticmethod
    def build_error_perspective_response_from_exception(
        remote_check_exception: RemoteCheckException,
    ) -> PerspectiveResponse:
        perspective = remote_check_exception.call_config.perspective
        check_type = remote_check_exception.call_config.check_type
        check_error_response = None

        errors = [
            MpicValidationError.create(ErrorMessages.COORDINATOR_REMOTE_CHECK_ERROR, remote_check_exception)
        ]

        match check_type:
            case CheckType.CAA:
                check_error_response = CaaCheckResponse(
                    check_completed=False,
                    check_passed=False,
                    errors=errors,
                    details=CaaCheckResponseDetails(caa_record_present=None),
                    timestamp_ns=time.time_ns(),
                )
            case CheckType.DCV:
                dcv_check_request: DcvCheckRequest = remote_check_exception.call_config.check_request
                validation_method = dcv_check_request.dcv_check_parameters.validation_method
                check_error_response = DcvCheckResponse(
                    check_completed=False,
                    check_passed=False,
                    errors=errors,
                    details=DcvCheckResponseDetailsBuilder.build_response_details(validation_method),
                    timestamp_ns=time.time_ns(),
                )

        return PerspectiveResponse(perspective_code=perspective.code, check_response=check_error_response)

    # Issues the async calls to the remote perspectives and collects the responses.
    async def call_checkers_and_collect_responses(
        self, mpic_request, perspectives_to_use, async_calls_to_issue
    ) -> list[PerspectiveResponse]:
        perspective_responses = []

        tasks = [
            self.call_remote_perspective(self.call_remote_perspective_function, call_config)
            for call_config in async_calls_to_issue
        ]

        # noinspection PyUnresolvedReferences
        async with self.logger.trace_timing(f"MPIC round-trip with {len(perspectives_to_use)} perspectives"):
            responses = await asyncio.gather(*tasks, return_exceptions=True)

        for response in responses:
            # check for exception (return_exceptions=True above will return exceptions as responses)
            # every Exception should be rethrown as RemoteCheckException
            # (trying to handle other Exceptions should be unreachable code)
            if isinstance(response, RemoteCheckException):
                response_as_string = str(response)
                log_msg = f"{response_as_string} - Trace identifier: {mpic_request.trace_identifier}"
                logger.warning(log_msg)
                error_response = MpicCoordinator.build_error_perspective_response_from_exception(response)
                perspective_responses.append(error_response)
            else:
                # Now we know it's a valid PerspectiveResponse
                perspective_responses.append(response)

        return perspective_responses
