import logging
from io import StringIO

import pytest
from opentelemetry import trace
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import SimpleSpanProcessor, ConsoleSpanExporter
from opentelemetry.sdk.trace.export.in_memory_span_exporter import InMemorySpanExporter

from open_mpic_core.common_util.trace_level_logger import TRACE_LEVEL


@pytest.fixture(autouse=False)
def logging_output():
    # Clear existing handlers
    root = logging.getLogger()
    for handler in root.handlers[:]:
        root.removeHandler(handler)

    # noinspection PyAttributeOutsideInit
    log_output = StringIO()  # to be able to inspect what gets logged
    handler = logging.StreamHandler(log_output)
    handler.setFormatter(logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s'))

    # Configure fresh logging
    logging.basicConfig(
        level=TRACE_LEVEL,
        handlers=[handler]
    )
    yield log_output


@pytest.fixture(scope='session', autouse=False)
def tracer_provider():
    provider = TracerProvider()
    trace.set_tracer_provider(provider)
    yield provider
    provider.shutdown()


@pytest.fixture(autouse=False, scope='function')
def tracer_console_exporter(tracer_provider):  # use for DEBUGGING OpenTelemetry related tests (to see what gets logged)
    exporter = ConsoleSpanExporter()
    processor = SimpleSpanProcessor(exporter)
    tracer_provider.add_span_processor(processor)
    yield
    processor.shutdown()


@pytest.fixture(autouse=False, scope='function')
def tracer_in_memory_exporter(tracer_provider):  # use for assertions in OpenTelemetry tests
    exporter = InMemorySpanExporter()
    processor = SimpleSpanProcessor(exporter)  # Using Simple instead of Batch for immediate processing
    tracer_provider.add_span_processor(processor)
    yield exporter
    exporter.clear()
    processor.shutdown()
