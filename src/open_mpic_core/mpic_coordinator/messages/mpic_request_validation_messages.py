from enum import Enum


class MpicRequestValidationMessages(Enum):
    INVALID_PERSPECTIVE_COUNT = ("invalid-perspective-count", "Invalid perspective count: {0}")
    INVALID_QUORUM_COUNT = ("invalid-quorum-count", "Invalid quorum count: {0}")
    INVALID_CERTIFICATE_TYPE = ("invalid-certificate-type", "Invalid 'certificate-type' specified: {0}")
    INVALID_VALIDATION_METHOD_RECORD_TYPE_COMBINATION = (
        "invalid-validation-method-record-type-combination",
        "Invalid validation method and record type combination: {0} and {1}",
    )
    REQUEST_VALIDATION_FAILED = ("request-validation-failed", "Request validation failed.")
    EMPTY_CHALLENGE_VALUE = ("empty-challenge-value", "Empty challenge value.")

    def __init__(self, key, message):
        self.key = key
        self.message = message
