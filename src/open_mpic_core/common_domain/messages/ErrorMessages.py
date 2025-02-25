from enum import Enum


class ErrorMessages(Enum):
    CAA_LOOKUP_ERROR = ('mpic_error:caa_checker:lookup', 'There was an error looking up the CAA record.')
    COORDINATOR_COMMUNICATION_ERROR = ('mpic_error:coordinator:communication', 'Communication with the remote perspective failed.')
    COORDINATOR_REMOTE_CHECK_ERROR = ('mpic_error:coordinator:remote_check', 'The remote check failed to complete (see remote perspective logs).')

    def __init__(self, key, message):
        self.key = key
        self.message = message
