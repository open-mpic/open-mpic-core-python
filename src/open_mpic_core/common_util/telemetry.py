"""OpenTelemetry accessor helpers for open-mpic-core.

Depends only on ``opentelemetry-api``.  When no SDK provider is registered the
returned Meter/Tracer objects are silent no-ops — the library is safe to use
without any OTEL configuration.

Container services configure real providers at startup (before any requests are
processed), after which every ``get_meter`` / ``get_tracer`` call in the core
routes through those providers automatically.
"""

from open_mpic_core.__about__ import __version__
from opentelemetry import metrics, trace

_INSTRUMENTATION_VERSION: str = __version__


def get_meter(name: str) -> metrics.Meter:
    """Return a :class:`~opentelemetry.metrics.Meter` scoped to *name*.

    Resolves through the global ``MeterProvider``; returns a no-op Meter when
    no SDK provider has been registered.
    """
    return metrics.get_meter(name, version=_INSTRUMENTATION_VERSION)


def get_tracer(name: str) -> trace.Tracer:
    """Return a :class:`~opentelemetry.trace.Tracer` scoped to *name*.

    Resolves through the global ``TracerProvider``; returns a no-op Tracer when
    no SDK provider has been registered.
    """
    return trace.get_tracer(name, instrumenting_library_version=_INSTRUMENTATION_VERSION)
