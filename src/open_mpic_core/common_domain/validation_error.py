from pydantic import BaseModel


class MpicValidationError(BaseModel):
    error_type: str
    error_message: str

    @classmethod
    def create(cls, error_type, *message_args):
        return cls(
            error_type = error_type.key,
            error_message = error_type.message.format(*message_args)
        )
