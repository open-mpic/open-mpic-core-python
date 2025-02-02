from open_mpic_core import RemoteCheckCallConfiguration


class RemoteCheckException(Exception):
    def __init__(self, message, call_config: RemoteCheckCallConfiguration):
        super().__init__(message)
        self.call_config = call_config
