from enum import Enum


class ErrorMessages(Enum):
    CAA_LOOKUP_ERROR = ('mpic_error:caa_checker:lookup', 'There was an error looking up the CAA record: {0}')
    DCV_LOOKUP_ERROR = ('mpic_error:dcv_checker:lookup', 'There was an error looking up the DCV record. Error type: {0}, Error message: {1}')
    COORDINATOR_COMMUNICATION_ERROR = ('mpic_error:coordinator:communication', 'Communication with the remote perspective failed.')
    COORDINATOR_REMOTE_CHECK_ERROR = ('mpic_error:coordinator:remote_check', 'The remote check failed to complete: {0}')
    TOO_MANY_FAILED_PERSPECTIVES_ERROR = ('mpic_error:coordinator:too_many_failed_perspectives', 'Too many perspectives failed to complete the check.')
    GENERAL_HTTP_ERROR = ('mpic_error:http', 'An HTTP error occurred: Response status {0}, Response reason: {1}')
    INVALID_REDIRECT_ERROR = ('mpic_error:redirect:invalid', 'Invalid redirect. Redirect code: {0}, target: {1}')

    def __init__(self, key, message):
        self.key = key
        self.message = message
