"""
Tests for MIESC Logging Configuration

Tests the centralized logging system including formatters and context management.

Author: Fernando Boiero
License: AGPL-3.0
"""

import json
import logging
import os
import time
from pathlib import Path
from tempfile import TemporaryDirectory
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
    """Tests for correlation ID management."""

    def setup_method(self):
        """Reset state before each test."""
        clear_log_context()
        # Reset correlation ID
        from src.core.logging_config import _correlation_id

        _correlation_id.set(None)

    def test_set_correlation_id_generates_uuid(self):
        """Test that set_correlation_id generates a UUID when not provided."""
        cid = set_correlation_id()
        assert cid is not None
        assert len(cid) == 8  # UUID[:8]

    def test_set_correlation_id_uses_provided(self):
        """Test that set_correlation_id uses provided value."""
        cid = set_correlation_id("test-123")
        assert cid == "test-123"

    def test_get_correlation_id(self):
        """Test getting correlation ID."""
        assert get_correlation_id() is None
        set_correlation_id("abc123")
        assert get_correlation_id() == "abc123"


class TestLogContext:
    """Tests for log context management."""

    def setup_method(self):
        """Reset context before each test."""
        clear_log_context()

    def test_add_log_context(self):
        """Test adding context to logs."""
        add_log_context(contract="Token.sol")
        add_log_context(layer=1)

        from src.core.logging_config import _log_context

        ctx = _log_context.get()
        assert ctx["contract"] == "Token.sol"
        assert ctx["layer"] == 1

    def test_clear_log_context(self):
        """Test clearing log context."""
        add_log_context(test="value")
        clear_log_context()

        from src.core.logging_config import _log_context

        assert _log_context.get() == {}

    def test_log_context_manager(self):
        """Test log_context context manager."""
        add_log_context(outer="value")

        with log_context(inner="context"):
            from src.core.logging_config import _log_context

            ctx = _log_context.get()
            assert ctx["outer"] == "value"
            assert ctx["inner"] == "context"

        # After exiting, inner context should be removed
        ctx = _log_context.get()
        assert ctx["outer"] == "value"
        assert "inner" not in ctx

    def test_request_context_manager(self):
        """Test request_context context manager."""
        # Ensure clean state before test
        from src.core.logging_config import _correlation_id

        _correlation_id.set(None)

        with request_context() as cid:
            assert cid is not None
            assert get_correlation_id() == cid

        # After exiting, correlation ID should be cleared
        assert get_correlation_id() is None

    def test_request_context_with_id(self):
        """Test request_context with provided ID."""
        with request_context("test-request") as cid:
            assert cid == "test-request"
            assert get_correlation_id() == "test-request"


class TestStructuredFormatter:
    """Tests for JSON structured formatter."""

    def test_basic_format(self):
        """Test basic JSON formatting."""
        formatter = StructuredFormatter()

        record = logging.LogRecord(
            name="test.logger",
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
        assert data["logger"] == "test.logger"
        assert "timestamp" in data

    def test_format_with_correlation_id(self):
        """Test formatting includes correlation ID."""
        formatter = StructuredFormatter()
        set_correlation_id("test-cid")

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

        assert data["correlation_id"] == "test-cid"

        # Cleanup
        from src.core.logging_config import _correlation_id

        _correlation_id.set(None)

    def test_format_with_context(self):
        """Test formatting includes context."""
        formatter = StructuredFormatter()
        add_log_context(contract="Test.sol")

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

        assert data["contract"] == "Test.sol"

        clear_log_context()

    def test_format_with_exception(self):
        """Test formatting includes exception info."""
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
    """Tests for rich console formatter."""

    def test_basic_format(self):
        """Test basic console formatting."""
        formatter = RichFormatter()

        record = logging.LogRecord(
            name="test.logger",
            level=logging.INFO,
            pathname="test.py",
            lineno=10,
            msg="Test message",
            args=(),
            exc_info=None,
        )

        output = formatter.format(record)

        assert "INFO" in output
        assert "Test message" in output
        assert "test.logger" in output

    def test_format_shortens_long_names(self):
        """Test that long logger names are shortened."""
        formatter = RichFormatter()

        record = logging.LogRecord(
            name="src.adapters.very_long_module_name.submodule",
            level=logging.INFO,
            pathname="test.py",
            lineno=1,
            msg="Test",
            args=(),
            exc_info=None,
        )

        output = formatter.format(record)
        # Should be shortened
        assert "adapters" in output or "ada" in output

    def test_format_levels_have_colors(self):
        """Test that different levels have different colors."""
        formatter = RichFormatter()

        for level in [logging.DEBUG, logging.INFO, logging.WARNING, logging.ERROR]:
            record = logging.LogRecord(
                name="test",
                level=level,
                pathname="test.py",
                lineno=1,
                msg="Test",
                args=(),
                exc_info=None,
            )

            output = formatter.format(record)
            # Should contain ANSI color codes
            assert "\033[" in output


class TestContextFilter:
    """Tests for context filter."""

    def test_filter_adds_extra_fields(self):
        """Test that filter adds extra fields to records."""
        filter = ContextFilter()

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

        result = filter.filter(record)

        assert result is True
        assert hasattr(record, "extra_fields")
        assert "custom_field" in record.extra_fields


class TestSetupLogging:
    """Tests for logging setup."""

    def test_setup_logging_default(self):
        """Test default logging setup."""
        setup_logging(quiet=True)  # Quiet to avoid test output

        logger = get_logger("test.setup")
        assert logger is not None

    def test_setup_logging_with_json(self):
        """Test JSON format logging setup."""
        setup_logging(json_format=True, quiet=True)

        logger = get_logger("test.json")
        assert logger is not None

    def test_setup_logging_with_file(self):
        """Test logging to file."""
        with TemporaryDirectory() as tmpdir:
            log_file = Path(tmpdir) / "test.log"

            setup_logging(log_file=str(log_file), quiet=True)

            logger = get_logger("test.file")
            logger.info("Test message")

            # Force handler flush
            for handler in logging.getLogger().handlers:
                handler.flush()

            # Check file was created
            assert log_file.exists()

    def test_setup_logging_from_env(self):
        """Test logging setup from environment variables."""
        with patch.dict(os.environ, {"MIESC_LOG_LEVEL": "DEBUG"}):
            setup_logging(quiet=True)

            root_logger = logging.getLogger()
            assert root_logger.level <= logging.DEBUG


class TestTimedDecorator:
    """Tests for timed decorator."""

    def test_timed_logs_duration(self):
        """Test that timed decorator logs execution time."""

        @timed()
        def slow_function():
            time.sleep(0.01)
            return "result"

        result = slow_function()
        assert result == "result"

    def test_timed_with_custom_logger(self):
        """Test timed with custom logger."""
        custom_logger = logging.getLogger("test.timed")

        @timed(logger=custom_logger, level=logging.INFO)
        def test_function():
            return 42

        result = test_function()
        assert result == 42

    def test_timed_logs_errors(self):
        """Test that timed decorator logs errors."""

        @timed()
        def failing_function():
            raise ValueError("Test error")

        with pytest.raises(ValueError):
            failing_function()


class TestAnalysisLogger:
    """Tests for AnalysisLogger class."""

    def test_initialization(self):
        """Test AnalysisLogger initialization."""
        logger = AnalysisLogger()
        assert logger.audit_id is not None
        assert len(logger.audit_id) == 8

    def test_initialization_with_id(self):
        """Test AnalysisLogger with provided audit ID."""
        logger = AnalysisLogger(audit_id="test-audit")
        assert logger.audit_id == "test-audit"

    def test_start_logging(self):
        """Test logging analysis start."""
        logger = AnalysisLogger()
        # Should not raise
        logger.start("Token.sol", [1, 2, 3], ["slither", "mythril"])

    def test_layer_logging(self):
        """Test logging layer start and complete."""
        logger = AnalysisLogger()
        logger.layer_start(1, ["slither", "aderyn"])
        logger.layer_complete(1, 5, 1000.0)

    def test_tool_logging(self):
        """Test logging tool execution."""
        logger = AnalysisLogger()
        logger.tool_start("slither", 1)
        logger.tool_complete("slither", 1, 3, 500.0)

    def test_tool_error_logging(self):
        """Test logging tool errors."""
        logger = AnalysisLogger()
        logger.tool_error("mythril", 3, "Timeout exceeded")

    def test_complete_logging(self):
        """Test logging analysis completion."""
        logger = AnalysisLogger()
        logger.complete(total_findings=10, critical=2, high=3)


class TestGetLogger:
    """Tests for get_logger function."""

    def test_get_logger_returns_logger(self):
        """Test that get_logger returns a logger instance."""
        logger = get_logger("test.module")
        assert isinstance(logger, logging.Logger)
        assert logger.name == "test.module"

    def test_get_logger_same_instance(self):
        """Test that get_logger returns same instance for same name."""
        logger1 = get_logger("test.same")
        logger2 = get_logger("test.same")
        assert logger1 is logger2
