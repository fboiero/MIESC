"""Tests for the plugin protocol: metadata round-trip, context callbacks, and a
minimal concrete plugin exercising the MIESCPlugin base class."""

from __future__ import annotations

from miesc.plugins.protocol import (
    MIESCPlugin,
    PluginContext,
    PluginMetadata,
    PluginResult,
    PluginState,
    PluginType,
)


class _DummyPlugin(MIESCPlugin):
    @property
    def name(self) -> str:
        return "dummy"

    @property
    def version(self) -> str:
        return "1.0.0"

    @property
    def plugin_type(self) -> PluginType:
        return PluginType.DETECTOR

    def initialize(self, context: PluginContext) -> None:
        self._context = context
        self._state = PluginState.INITIALIZED

    def execute(self, *args, **kwargs) -> PluginResult:
        return PluginResult(success=True, data={"ran": True})


class TestPluginMetadata:
    def test_roundtrip(self):
        meta = PluginMetadata(
            name="p",
            version="1.0.0",
            plugin_type=PluginType.DETECTOR,
            description="d",
            author="a",
        )
        restored = PluginMetadata.from_dict(meta.to_dict())
        assert restored.name == "p"
        assert restored.plugin_type == PluginType.DETECTOR


class TestPluginContext:
    def test_callbacks_and_services(self):
        findings, progress, logs = [], [], []
        ctx = PluginContext(
            miesc_version="5.4",
            config={},
            data_dir="/tmp",
            cache_dir="/tmp",
            on_finding=findings.append,
            on_progress=lambda p, m="": progress.append((p, m)),
            on_log=lambda lvl, msg: logs.append((lvl, msg)),
            services={"db": object()},
        )
        ctx.report_finding({"type": "x"})
        ctx.report_progress(0.5, "halfway")
        ctx.log("info", "hello")
        assert findings and progress and logs
        assert ctx.get_service("db") is not None
        assert ctx.get_service("missing") is None


class TestConcretePlugin:
    def test_properties_and_lifecycle(self):
        p = _DummyPlugin()
        assert p.name == "dummy"
        assert p.plugin_type == PluginType.DETECTOR
        ctx = PluginContext(miesc_version="5.4", config={}, data_dir="/tmp", cache_dir="/tmp")
        p.initialize(ctx)
        assert p.context is ctx
        result = p.execute()
        assert result.success is True
        # default config + validate + cleanup don't raise
        assert isinstance(p.config, dict)
        assert isinstance(p.validate_config({}), list)
        p.cleanup()
