from abc import ABC
from pydantic import BaseModel


class BaseMpicOrchestrationParameters(BaseModel, ABC):
    perspective_count: int | None = None
    quorum_count: int | None = None


class MpicRequestOrchestrationParameters(BaseMpicOrchestrationParameters):
    max_attempts: int | None = None
    cohort_for_single_attempt: int | None = None  # sets max_attempts to 1 if defined; must be > 0


class MpicEffectiveOrchestrationParameters(BaseMpicOrchestrationParameters):
    attempt_count: int | None = 1
