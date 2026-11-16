"""
Structured logging setup.

Design decision: JSON-formatted logs in non-development environments so
they're directly ingestible by log aggregators (ELK, CloudWatch, Datadog)
without a separate parsing step. Human-readable logs in dev for fast
iteration. This mirrors how real security products log — audit trails and
error logs must be machine-parseable, not just human-pretty.
"""
import json
import logging
import sys
from datetime import datetime, timezone

from app.core.config import get_settings

settings = get_settings()


class JsonFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        payload = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
            "module": record.module,
            "function": record.funcName,
            "line": record.lineno,
        }
        if record.exc_info:
            payload["exception"] = self.formatException(record.exc_info)
        # Allow callers to attach extra structured context, e.g.
        # logger.info("scan imported", extra={"context": {"asset_count": 42}})
        if hasattr(record, "context"):
            payload["context"] = record.context
        return json.dumps(payload)


def configure_logging() -> None:
    root = logging.getLogger()
    root.setLevel(settings.LOG_LEVEL)

    # Remove any pre-existing handlers (uvicorn attaches its own by default)
    root.handlers.clear()

    handler = logging.StreamHandler(sys.stdout)
    if settings.APP_ENV == "development":
        handler.setFormatter(
            logging.Formatter("%(asctime)s | %(levelname)-8s | %(name)s | %(message)s")
        )
    else:
        handler.setFormatter(JsonFormatter())

    root.addHandler(handler)
