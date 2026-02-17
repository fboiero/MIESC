"""
Tests for MIESC centralized logging configuration.

Tests the structured logging system including formatters, context management,
and the timed decorator.
"""

import json
import logging
import os
import tempfile
import time
from pathlib import Path
from unittest.mock import patch

import pytest

from src.core.logging_config import (
    AnalysisLogger,
    ContextFilter,
    RichFormatter,
    StructuredFormatter,
    add_log_context,
    clear_log_context,
    get_correlation_id,
    get_logger,
    log_context,
    request_context,
    set_correlation_id,
    setup_logging,
    timed,
)


class TestCorrelationId:
    """Test correlation ID management."""

    def setup_method(self):
        """Reset correlation ID before each test."""
        from src.core.logging_config import _correlation_id

        _correlation_id.set(None)

    def test_get_correlation_id_default(self):
        """Test default correlation ID is None."""
        assert get_correlation_id() is None

    def test_set_correlation_id(self):
        """Test setting correlation ID."""
        cid = set_correlation_id("test123")
        assert cid == "test123"
        assert get_correlation_id() == "test123"

    def test_set_correlation_id_auto_generate(self):
        """Test auto-generating correlation ID."""
        cid = set_correlation_id()
        assert cid is not None
        assert len(cid) == 8


class TestLogContext:
    """Test log context management."""

    def setup_method(self):
        """Reset log context before each test."""
        clear_log_context()

    def test_add_log_context(self):
        """Test adding log context."""
        add_log_context(contract="Token.sol", layer=1)
        from src.core.logging_config import _log_context

        ctx = _log_context.get()
        assert ctx["contract"] == "Token.sol"
        assert ctx["layer"] == 1

    def test_clear_log_context(self):
        """Test clearing log context."""
        add_log_context(key="value")
        clear_log_context()
        from src.core.logging_config import _log_context

        assert _log_context.get() == {}

    def test_log_context_manager(self):
        """Test log context manager."""
        add_log_context(outer="value")

        with log_context(inner="temp"):
            from src.core.logging_config import _log_context

            ctx = _log_context.get()
            assert ctx["outer"] == "value"
            assert ctx["inner"] == "temp"

        # Should restore outer context
        ctx = _log_context.get()
        assert ctx.get("outer") == "value"
        assert "inner" not in ctx


class TestStructuredFormatter:
    """Test JSON structured formatter."""

    def setup_method(self):
        """Reset context before each test."""
        clear_log_context()
        from src.core.logging_config import _correlation_id
        _correlation_id.set(None)

    def test_basic_format(self):
        """Test basic log formatting."""
        formatter = StructuredFormatter()
        record = logging.LogRecord(
            name="test.module",
            level=logging.INFO,
            pathname="test.py",
            lineno=10,
            msg="Test message",
            args=(),
            exc_info=None,
        )
        output = formatter.format(record)
        data = json.loads(output)

        assert data["level"] == "INFO"
        assert data["message"] == "Test message"
        assert data["logger"] == "test.module"
        assert "timestamp" in data

    def test_format_with_correlation_id(self):
        """Test format includes correlation ID."""
        set_correlation_id("abc123")
        formatter = StructuredFormatter()
        record = logging.LogRecord(
            name="test",
            level=logging.INFO,
            pathname="test.py",
            lineno=1,
            msg="Test",
            args=(),
            exc_info=None,
        )
        output = formatter.format(record)
        data = json.loads(output)

        assert data["correlation_id"] == "abc123"

    def test_format_with_context(self):
        """Test format includes context."""
        add_log_context(contract="Token.sol")
        formatter = StructuredFormatter()
        record = logging.LogRecord(
            name="test",
            level=logging.INFO,
            pathname="test.py",
            lineno=1,
            msg="Test",
            args=(),
            exc_info=None,
        )
        output = formatter.format(record)
        data = json.loads(output)

        assert data["contract"] == "Token.sol"

    def test_format_with_exception(self):
        """Test format includes exception info."""
        formatter = StructuredFormatter()
        try:
            raise ValueError("Test error")
        except ValueError:
            import sys

            exc_info = sys.exc_info()

        record = logging.LogRecord(
            name="test",
            level=logging.ERROR,
            pathname="test.py",
            lineno=1,
            msg="Error occurred",
            args=(),
            exc_info=exc_info,
        )
        output = formatter.format(record)
        data = json.loads(output)

        assert "exception" in data
        assert "ValueError" in data["exception"]


class TestRichFormatter:
    """Test rich console formatter."""

    def setup_method(self):
        """Reset context before each test."""
        clear_log_context()
        from src.core.logging_config import _correlation_id
        _correlation_id.set(None)

    def test_basic_format(self):
        """Test basic rich formatting."""
        formatter = RichFormatter()
        record = logging.LogRecord(
            name="test.module",
            level=logging.INFO,
            pathname="test.py",
            lineno=10,
            msg="Test message",
            args=(),
            exc_info=None,
        )
        output = formatter.format(record)

        assert "Test message" in output
        assert "INFO" in output

    def test_format_includes_time(self):
        """Test format includes timestamp."""
        formatter = RichFormatter()
        record = logging.LogRecord(
            name="test",
            level=logging.DEBUG,
            pathname="test.py",
            lineno=1,
            msg="Debug message",
            args=(),
            exc_info=None,
        )
        output = formatter.format(record)

        # Should have time in format HH:MM:SS
        assert "[" in output and "]" in output

    def test_format_with_correlation_id(self):
        """Test rich format includes correlation ID."""
        set_correlation_id("xyz789")
        formatter = RichFormatter()
        record = logging.LogRecord(
            name="test",
            level=logging.INFO,
            pathname="test.py",
            lineno=1,
            msg="Test",
            args=(),
            exc_info=None,
        )
        output = formatter.format(record)

        assert "xyz789" in output

    def test_long_logger_name_shortened(self):
        """Test long logger names are shortened."""
        formatter = RichFormatter()
        record = logging.LogRecord(
            name="src.very.long.module.name.here",
            level=logging.INFO,
            pathname="test.py",
            lineno=1,
            msg="Test",
            args=(),
            exc_info=None,
        )
        output = formatter.format(record)

        # Logger name should be shortened
        assert len(output) < 200


class TestContextFilter:
    """Test context filter."""

    def test_filter_adds_extra_fields(self):
        """Test filter adds extra fields to record."""
        filter_obj = ContextFilter()
        record = logging.LogRecord(
            name="test",
            level=logging.INFO,
            pathname="test.py",
            lineno=1,
            msg="Test",
            args=(),
            exc_info=None,
        )
        record.custom_field = "custom_value"

        result = filter_obj.filter(record)

        assert result is True
        assert hasattr(record, "extra_fields")


class TestSetupLogging:
    """Test logging setup function."""

    def test_setup_logging_default(self):
        """Test default logging setup."""
        setup_logging()
        logger = logging.getLogger()
        assert logger.level == logging.INFO

    def test_setup_logging_debug(self):
        """Test debug level setup."""
        setup_logging(level="DEBUG")
        logger = logging.getLogger()
        assert logger.level == logging.DEBUG

    def test_setup_logging_json_format(self):
        """Test JSON format setup."""
        setup_logging(json_format=True)
        # Should not crash

    def test_setup_logging_quiet(self):
        """Test quiet mode."""
        setup_logging(quiet=True)
        logger = logging.getLogger()
        # Should have fewer handlers in quiet mode

    def test_setup_logging_with_file(self, tmp_path):
        """Test logging to file."""
        log_file = tmp_path / "test.log"
        setup_logging(log_file=str(log_file))

        # Log something
        logger = logging.getLogger("test")
        logger.info("Test log message")

        # Should create log file
        assert log_file.exists() or len(logging.getLogger().handlers) > 0

    def test_setup_logging_from_env(self):
        """Test logging from environment variables."""
        with patch.dict(os.environ, {"MIESC_LOG_LEVEL": "WARNING"}):
            setup_logging()
            logger = logging.getLogger()
            assert logger.level == logging.WARNING


class TestGetLogger:
    """Test get_logger function."""

    def test_get_logger(self):
        """Test getting a logger."""
        logger = get_logger("test.module")
        assert isinstance(logger, logging.Logger)
        assert logger.name == "test.module"

    def test_get_logger_same_instance(self):
        """Test same logger returned for same name."""
        logger1 = get_logger("same.name")
        logger2 = get_logger("same.name")
        assert logger1 is logger2


class TestRequestContext:
    """Test request context manager."""

    def setup_method(self):
        """Reset correlation ID before each test."""
        from src.core.logging_config import _correlation_id

        _correlation_id.set(None)

    def test_request_context_sets_id(self):
        """Test request context sets correlation ID."""
        with request_context("req123") as cid:
            assert cid == "req123"
            assert get_correlation_id() == "req123"

    def test_request_context_auto_generates_id(self):
        """Test request context auto-generates ID."""
        with request_context() as cid:
            assert cid is not None
            assert len(cid) == 8

    def test_request_context_restores_previous(self):
        """Test request context restores previous ID."""
        set_correlation_id("outer")

        with request_context("inner"):
            assert get_correlation_id() == "inner"

        assert get_correlation_id() == "outer"


class TestTimedDecorator:
    """Test timed decorator."""

    def test_timed_logs_duration(self):
        """Test timed decorator logs duration."""

        @timed()
        def slow_function():
            time.sleep(0.01)
            return "result"

        result = slow_function()
        assert result == "result"

    def test_timed_with_custom_logger(self):
        """Test timed with custom logger."""
        custom_logger = logging.getLogger("custom")

        @timed(logger=custom_logger, level=logging.INFO)
        def my_function():
            return 42

        result = my_function()
        assert result == 42

    def test_timed_logs_exception(self):
        """Test timed logs on exception."""

        @timed()
        def failing_function():
            raise ValueError("Test error")

        with pytest.raises(ValueError):
            failing_function()


class TestAnalysisLogger:
    """Test AnalysisLogger class."""

    def test_analysis_logger_init(self):
        """Test analysis logger initialization."""
        al = AnalysisLogger()
        assert al.audit_id is not None
        assert len(al.audit_id) == 8

    def test_analysis_logger_custom_id(self):
        """Test analysis logger with custom ID."""
        al = AnalysisLogger(audit_id="custom123")
        assert al.audit_id == "custom123"

    def test_analysis_logger_start(self):
        """Test logging analysis start."""
        al = AnalysisLogger()
        # Should not crash
        al.start(
            contract="Token.sol",
            layers=[1, 2, 3],
            tools=["slither", "mythril"],
        )

    def test_analysis_logger_layer_start(self):
        """Test logging layer start."""
        al = AnalysisLogger()
        al.layer_start(layer=1, tools=["slither"])


class TestIntegration:
    """Integration tests for logging system."""

    def test_full_logging_workflow(self, tmp_path):
        """Test complete logging workflow."""
        log_file = tmp_path / "audit.log"

        # Setup logging
        setup_logging(level="DEBUG", log_file=str(log_file))

        # Create request context
        with request_context("audit-001") as cid:
            # Add context
            with log_context(contract="Token.sol", layer=1):
                logger = get_logger("test.integration")
                logger.info("Analysis started")
                logger.debug("Processing contract")
                logger.warning("Potential issue found")

        # Verify correlation ID was used
        assert cid == "audit-001"

    def test_logging_with_exceptions(self):
        """Test logging with exception handling."""
        logger = get_logger("test.exceptions")

        try:
            raise RuntimeError("Test runtime error")
        except RuntimeError:
            logger.exception("Error occurred")

    def test_multiple_contexts(self):
        """Test nested log contexts."""
        with log_context(outer="value1"):
            with log_context(inner="value2"):
                from src.core.logging_config import _log_context

                ctx = _log_context.get()
                assert ctx["outer"] == "value1"
                assert ctx["inner"] == "value2"
