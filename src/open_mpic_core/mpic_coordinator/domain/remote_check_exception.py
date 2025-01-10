from open_mpic_core.mpic_coordinator.domain.remote_check_call_configuration import RemoteCheckCallConfiguration


class RemoteCheckException(Exception):
    def __init__(self, message, call_config: RemoteCheckCallConfiguration):
        super().__init__(message)
        self.call_config = call_config
