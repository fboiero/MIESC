"""
MIESC - Centralized Logging Configuration

This module provides a unified logging system for MIESC with:
- Structured JSON logging for production
- Rich console logging for development
- Correlation IDs for request tracing
- Automatic context enrichment
- Performance timing utilities

Usage:
    from src.core.logging_config import get_logger, setup_logging

    # Setup logging at application start
    setup_logging(level="DEBUG", json_format=False)

    # Get a logger for your module
    logger = get_logger(__name__)

    # Log with context
    logger.info("Analysis started", extra={"contract": "Token.sol", "layer": 1})

Environment Variables:
    MIESC_LOG_LEVEL: Set log level (DEBUG, INFO, WARNING, ERROR, CRITICAL)
    MIESC_LOG_FORMAT: Set format ('json' or 'console')
    MIESC_LOG_FILE: Path to log file (optional)
"""

import json
import logging
import os
import sys
import time
import uuid
from contextlib import contextmanager
from contextvars import ContextVar
from datetime import datetime
from functools import wraps
from pathlib import Path
from typing import Any, Callable, Dict, Optional

# Context variable for correlation ID (request tracing)
_correlation_id: ContextVar[Optional[str]] = ContextVar("correlation_id", default=None)

# Context variable for additional context
_log_context: ContextVar[Dict[str, Any]] = ContextVar("log_context", default={})


def get_correlation_id() -> Optional[str]:
    """Get the current correlation ID for request tracing."""
    return _correlation_id.get()


def set_correlation_id(correlation_id: Optional[str] = None) -> str:
    """Set a correlation ID for request tracing. Generates one if not provided."""
    if correlation_id is None:
        correlation_id = str(uuid.uuid4())[:8]
    _correlation_id.set(correlation_id)
    return correlation_id


def add_log_context(**kwargs: Any) -> None:
    """Add context to all subsequent log messages in this context."""
    current = _log_context.get().copy()
    current.update(kwargs)
    _log_context.set(current)


def clear_log_context() -> None:
    """Clear all log context."""
    _log_context.set({})


class StructuredFormatter(logging.Formatter):
    """
    JSON formatter for structured logging.

    Produces log lines like:
    {"timestamp": "2025-01-15T10:30:45Z", "level": "INFO", "message": "...", ...}
    """

    def format(self, record: logging.LogRecord) -> str:
        log_data = {
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
        }

        # Add correlation ID if available
        correlation_id = get_correlation_id()
        if correlation_id:
            log_data["correlation_id"] = correlation_id

        # Add context from ContextVar
        context = _log_context.get()
        if context:
            log_data.update(context)

        # Add extra fields from record
        if hasattr(record, "extra_fields"):
            log_data.update(record.extra_fields)

        # Add standard fields
        log_data.update({
            "file": record.filename,
            "line": record.lineno,
            "function": record.funcName,
        })

        # Add exception info if present
        if record.exc_info:
            log_data["exception"] = self.formatException(record.exc_info)

        return json.dumps(log_data, default=str)


class RichFormatter(logging.Formatter):
    """
    Rich console formatter with colors and icons.

    Produces log lines like:
    [10:30:45] INFO     module_name: Message here [context: value]
    """

    LEVEL_COLORS = {
        "DEBUG": "\033[36m",    # Cyan
        "INFO": "\033[32m",     # Green
        "WARNING": "\033[33m",  # Yellow
        "ERROR": "\033[31m",    # Red
        "CRITICAL": "\033[35m", # Magenta
    }
    RESET = "\033[0m"

    LEVEL_ICONS = {
        "DEBUG": "🔍",
        "INFO": "ℹ️ ",
        "WARNING": "⚠️ ",
        "ERROR": "❌",
        "CRITICAL": "🔥",
    }

    def format(self, record: logging.LogRecord) -> str:
        # Time
        time_str = datetime.now().strftime("%H:%M:%S")

        # Level with color
        color = self.LEVEL_COLORS.get(record.levelname, "")
        icon = self.LEVEL_ICONS.get(record.levelname, "")
        level = f"{color}{record.levelname:8}{self.RESET}"

        # Logger name (shortened)
        logger_name = record.name
        if logger_name.startswith("src."):
            logger_name = logger_name[4:]
        if len(logger_name) > 20:
            parts = logger_name.split(".")
            logger_name = ".".join(p[:3] for p in parts[:-1]) + "." + parts[-1]

        # Message
        message = record.getMessage()

        # Build the log line
        line = f"[{time_str}] {icon} {level} {logger_name}: {message}"

        # Add correlation ID
        correlation_id = get_correlation_id()
        if correlation_id:
            line += f" [{correlation_id}]"

        # Add context
        context = _log_context.get()
        if context:
            ctx_str = " ".join(f"{k}={v}" for k, v in context.items())
            line += f" ({ctx_str})"

        # Add extra fields
        if hasattr(record, "extra_fields") and record.extra_fields:
            extra_str = " ".join(f"{k}={v}" for k, v in record.extra_fields.items())
            line += f" [{extra_str}]"

        # Add exception
        if record.exc_info:
            line += "\n" + self.formatException(record.exc_info)

        return line


class ContextFilter(logging.Filter):
    """Filter that adds extra fields to log records."""

    def filter(self, record: logging.LogRecord) -> bool:
        # Extract extra fields from record
        extra_fields = {}
        for key, value in record.__dict__.items():
            if key not in logging.LogRecord(
                "", 0, "", 0, "", (), None
            ).__dict__ and key not in ("message", "asctime", "extra_fields"):
                if not key.startswith("_"):
                    extra_fields[key] = value

        record.extra_fields = extra_fields
        return True


def setup_logging(
    level: str = "INFO",
    json_format: bool = False,
    log_file: Optional[str] = None,
    quiet: bool = False
) -> None:
    """
    Configure MIESC logging.

    Args:
        level: Log level (DEBUG, INFO, WARNING, ERROR, CRITICAL)
        json_format: Use JSON format (for production/log aggregation)
        log_file: Path to log file (optional)
        quiet: Suppress console output
    """
    # Get settings from environment
    level = os.environ.get("MIESC_LOG_LEVEL", level).upper()
    json_format = os.environ.get("MIESC_LOG_FORMAT", "json" if json_format else "console") == "json"
    log_file = os.environ.get("MIESC_LOG_FILE", log_file)

    # Get root logger for MIESC
    root_logger = logging.getLogger()
    root_logger.setLevel(getattr(logging, level, logging.INFO))

    # Clear existing handlers
    root_logger.handlers.clear()

    # Create formatter
    if json_format:
        formatter = StructuredFormatter()
    else:
        formatter = RichFormatter()

    # Add context filter
    context_filter = ContextFilter()

    # Console handler
    if not quiet:
        console_handler = logging.StreamHandler(sys.stderr)
        console_handler.setFormatter(formatter)
        console_handler.addFilter(context_filter)
        root_logger.addHandler(console_handler)

    # File handler
    if log_file:
        log_path = Path(log_file)
        log_path.parent.mkdir(parents=True, exist_ok=True)
        file_handler = logging.FileHandler(log_file)
        file_handler.setFormatter(StructuredFormatter())  # Always JSON for files
        file_handler.addFilter(context_filter)
        root_logger.addHandler(file_handler)

    # Suppress noisy loggers
    logging.getLogger("urllib3").setLevel(logging.WARNING)
    logging.getLogger("httpx").setLevel(logging.WARNING)
    logging.getLogger("httpcore").setLevel(logging.WARNING)
    logging.getLogger("asyncio").setLevel(logging.WARNING)


def get_logger(name: str) -> logging.Logger:
    """
    Get a logger with the given name.

    Args:
        name: Logger name (typically __name__)

    Returns:
        Configured logger instance
    """
    return logging.getLogger(name)


@contextmanager
def log_context(**kwargs: Any):
    """
    Context manager for temporarily adding context to logs.

    Usage:
        with log_context(contract="Token.sol", layer=1):
            logger.info("Starting analysis")
            # ... do work ...
            logger.info("Analysis complete")
    """
    old_context = _log_context.get().copy()
    add_log_context(**kwargs)
    try:
        yield
    finally:
        _log_context.set(old_context)


@contextmanager
def request_context(correlation_id: Optional[str] = None):
    """
    Context manager for request-scoped logging with correlation ID.

    Usage:
        with request_context() as cid:
            logger.info(f"Request started: {cid}")
            # ... handle request ...
    """
    old_correlation_id = get_correlation_id()
    new_id = set_correlation_id(correlation_id)
    try:
        yield new_id
    finally:
        if old_correlation_id:
            set_correlation_id(old_correlation_id)
        else:
            _correlation_id.set(None)


def timed(logger: Optional[logging.Logger] = None, level: int = logging.DEBUG):
    """
    Decorator to log function execution time.

    Usage:
        @timed()
        def slow_function():
            time.sleep(1)

        @timed(logger=my_logger, level=logging.INFO)
        def important_function():
            pass
    """
    def decorator(func: Callable) -> Callable:
        _logger = logger or get_logger(func.__module__)

        @wraps(func)
        def wrapper(*args: Any, **kwargs: Any) -> Any:
            start_time = time.perf_counter()
            try:
                result = func(*args, **kwargs)
                elapsed = time.perf_counter() - start_time
                _logger.log(
                    level,
                    f"{func.__name__} completed",
                    extra={"duration_ms": round(elapsed * 1000, 2)}
                )
                return result
            except Exception as e:
                elapsed = time.perf_counter() - start_time
                _logger.log(
                    logging.ERROR,
                    f"{func.__name__} failed",
                    extra={
                        "duration_ms": round(elapsed * 1000, 2),
                        "error": str(e)
                    }
                )
                raise

        return wrapper
    return decorator


class AnalysisLogger:
    """
    Specialized logger for analysis operations.

    Provides structured logging for the audit workflow.
    """

    def __init__(self, audit_id: Optional[str] = None):
        self.logger = get_logger("miesc.analysis")
        self.audit_id = audit_id or str(uuid.uuid4())[:8]
        self.start_time = time.perf_counter()

    def start(self, contract: str, layers: list[int], tools: list[str]) -> None:
        """Log analysis start."""
        self.logger.info(
            "Analysis started",
            extra={
                "audit_id": self.audit_id,
                "contract": contract,
                "layers": layers,
                "tools": tools,
                "event": "analysis_start"
            }
        )

    def layer_start(self, layer: int, tools: list[str]) -> None:
        """Log layer execution start."""
        self.logger.info(
            f"Layer {layer} started",
            extra={
                "audit_id": self.audit_id,
                "layer": layer,
                "tools": tools,
                "event": "layer_start"
            }
        )

    def tool_start(self, tool: str, layer: int) -> None:
        """Log tool execution start."""
        self.logger.debug(
            f"Tool {tool} started",
            extra={
                "audit_id": self.audit_id,
                "tool": tool,
                "layer": layer,
                "event": "tool_start"
            }
        )

    def tool_complete(
        self,
        tool: str,
        layer: int,
        findings: int,
        duration_ms: float
    ) -> None:
        """Log tool execution complete."""
        self.logger.info(
            f"Tool {tool} complete: {findings} findings",
            extra={
                "audit_id": self.audit_id,
                "tool": tool,
                "layer": layer,
                "findings": findings,
                "duration_ms": duration_ms,
                "event": "tool_complete"
            }
        )

    def tool_error(self, tool: str, layer: int, error: str) -> None:
        """Log tool execution error."""
        self.logger.error(
            f"Tool {tool} failed: {error}",
            extra={
                "audit_id": self.audit_id,
                "tool": tool,
                "layer": layer,
                "error": error,
                "event": "tool_error"
            }
        )

    def layer_complete(self, layer: int, findings: int, duration_ms: float) -> None:
        """Log layer execution complete."""
        self.logger.info(
            f"Layer {layer} complete: {findings} findings",
            extra={
                "audit_id": self.audit_id,
                "layer": layer,
                "findings": findings,
                "duration_ms": duration_ms,
                "event": "layer_complete"
            }
        )

    def complete(self, total_findings: int, critical: int, high: int) -> None:
        """Log analysis complete."""
        elapsed = time.perf_counter() - self.start_time
        self.logger.info(
            f"Analysis complete: {total_findings} findings ({critical} critical, {high} high)",
            extra={
                "audit_id": self.audit_id,
                "total_findings": total_findings,
                "critical": critical,
                "high": high,
                "duration_s": round(elapsed, 2),
                "event": "analysis_complete"
            }
        )


__all__ = [
    # Setup
    "setup_logging",
    "get_logger",
    # Context management
    "get_correlation_id",
    "set_correlation_id",
    "add_log_context",
    "clear_log_context",
    "log_context",
    "request_context",
    # Utilities
    "timed",
    "AnalysisLogger",
    # Formatters
    "StructuredFormatter",
    "RichFormatter",
]
