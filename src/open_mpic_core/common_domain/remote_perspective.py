from pydantic import BaseModel


class RemotePerspective(BaseModel):
    code: str  # example: "us-west-2"
    # name seems to be an unused var and based on the spec the code seems to uniquely define a perspective.
    name: str | None = None  # example: "US West (Oregon)"
    rir: str  # example: "ARIN"
    too_close_codes: list[str] | None = []

    def is_perspective_too_close(self, perspective):
        return perspective.code in self.too_close_codes
