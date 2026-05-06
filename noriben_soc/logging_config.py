import logging
import json
from datetime import datetime
from typing import Any
from .config import settings

class JSONFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        data = {
            'timestamp': datetime.utcfromtimestamp(record.created).isoformat() + 'Z',
            'level': record.levelname,
            'logger': record.name,
            'message': record.getMessage(),
        }
        if record.exc_info:
            data['exc_info'] = self.formatException(record.exc_info)
        return json.dumps(data, default=str)


def configure_logging():
    level = getattr(logging, settings.LOG_LEVEL.upper(), logging.INFO)
    handler = logging.StreamHandler()
    if settings.LOG_JSON:
        handler.setFormatter(JSONFormatter())
    else:
        handler.setFormatter(logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s'))
    root = logging.getLogger()
    root.setLevel(level)
    # Remove existing handlers
    for h in list(root.handlers):
        root.removeHandler(h)
    root.addHandler(handler)

# Configure on import
configure_logging()
