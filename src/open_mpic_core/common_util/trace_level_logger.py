import logging

TRACE_LEVEL = 5
logging.addLevelName(TRACE_LEVEL, 'TRACE')


def get_logger(name: str) -> logging.Logger:
    """
        Returns a logger with trace capability added (if it doesn't exist).
        Use this instead of logging.getLogger() directly.
        :param name: logger name
    """
    if not hasattr(logging, 'TRACE'):
        logging.TRACE = TRACE_LEVEL

    if not hasattr(logging.Logger, 'trace'):
        def trace(self, message, *args, **kwargs):
            """Logs the provided message at TRACE_LEVEL."""
            if self.isEnabledFor(TRACE_LEVEL):
                self._log(TRACE_LEVEL, message, args, **kwargs)  # logger takes its '*args' as 'args'
        logging.Logger.trace = trace

    logger = logging.getLogger(name)
    return logger
