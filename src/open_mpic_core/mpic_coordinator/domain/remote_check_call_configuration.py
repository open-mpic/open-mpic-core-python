from open_mpic_core.common_domain.check_request import CheckRequest
from open_mpic_core.common_domain.enum.check_type import CheckType
from open_mpic_core.mpic_coordinator.domain.remote_perspective import RemotePerspective


class RemoteCheckCallConfiguration:
    def __init__(self, check_type: CheckType, perspective: RemotePerspective, check_request: CheckRequest):
        self.check_type = check_type
        self.perspective = perspective
        self.check_request = check_request
