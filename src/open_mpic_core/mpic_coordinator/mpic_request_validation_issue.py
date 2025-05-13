from open_mpic_core.mpic_coordinator.messages.mpic_request_validation_messages import MpicRequestValidationMessages


class MpicRequestValidationIssue:
    def __init__(self, validation_message: MpicRequestValidationMessages, *message_args):
        self.issue_type = validation_message.key
        self.message = validation_message.message.format(*message_args)
