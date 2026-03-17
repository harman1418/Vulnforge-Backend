"""
Logging configuration for VulnForge API
"""
import logging
import os
import json
from datetime import datetime

# Create logs directory
os.makedirs("logs", exist_ok=True)

# Logger setup
logger = logging.getLogger("vulnforge")
logger.setLevel(logging.INFO)

# Custom JSON formatter
class JSONFormatter(logging.Formatter):
    def format(self, record):
        log_obj = {
            "timestamp": datetime.utcnow().isoformat(),
            "level": record.levelname,
            "message": record.getMessage(),
        }
        # Add extra fields if present
        if hasattr(record, 'extra'):
            log_obj.update(record.extra)
        return json.dumps(log_obj)

# File handler with JSON formatting
file_handler = logging.FileHandler(f"logs/vulnforge_{datetime.now().strftime('%Y%m%d')}.log")
file_handler.setFormatter(JSONFormatter())

# Console handler
console_handler = logging.StreamHandler()
console_handler.setFormatter(logging.Formatter(
    '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
))

logger.addHandler(file_handler)
logger.addHandler(console_handler)


def log_info(message: str, **kwargs):
    """Log info level with extra data"""
    logger.info(message, extra={**kwargs})


def log_error(message: str, error: Exception = None, **kwargs):
    """Log error level with exception details"""
    extra = {"error": str(error)} if error else {}
    extra.update(kwargs)
    logger.error(message, extra=extra, exc_info=error is not None)


def log_warning(message: str, **kwargs):
    """Log warning level"""
    logger.warning(message, extra={**kwargs})


def log_debug(message: str, **kwargs):
    """Log debug level"""
    logger.debug(message, extra={**kwargs})


def log_security_event(event_type: str, user: str = None, ip: str = None, details: str = None):
    """Log security events"""
    log_info(
        f"SECURITY_EVENT: {event_type}",
        event_type=event_type,
        user=user,
        ip=ip,
        details=details
    )
