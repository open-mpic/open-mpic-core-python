from open_mpic_core import CheckRequest, CheckType, RemotePerspective


class RemoteCheckCallConfiguration:
    def __init__(self, check_type: CheckType, perspective: RemotePerspective, check_request: CheckRequest):
        self.check_type = check_type
        self.perspective = perspective
        self.check_request = check_request
