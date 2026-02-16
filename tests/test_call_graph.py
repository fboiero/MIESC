"""
Tests for src/ml/call_graph.py

Comprehensive tests for call graph construction and analysis including:
- Visibility and Mutability enums
- FunctionNode, CallEdge, CallPath dataclasses
- CallGraph class methods
- CallGraphBuilder class methods
- Convenience functions
"""

import pytest

from src.ml.call_graph import (
    Visibility,
    Mutability,
    FunctionNode,
    CallEdge,
    CallPath,
    CallGraph,
    CallGraphBuilder,
    build_call_graph,
    analyze_reentrancy_risk,
)


class TestVisibilityEnum:
    """Tests for Visibility enum."""

    def test_external(self):
        assert Visibility.EXTERNAL.value == "external"

    def test_public(self):
        assert Visibility.PUBLIC.value == "public"

    def test_internal(self):
        assert Visibility.INTERNAL.value == "internal"

    def test_private(self):
        assert Visibility.PRIVATE.value == "private"


class TestMutabilityEnum:
    """Tests for Mutability enum."""

    def test_payable(self):
        assert Mutability.PAYABLE.value == "payable"

    def test_nonpayable(self):
        assert Mutability.NONPAYABLE.value == "nonpayable"

    def test_view(self):
        assert Mutability.VIEW.value == "view"

    def test_pure(self):
        assert Mutability.PURE.value == "pure"


class TestFunctionNode:
    """Tests for FunctionNode dataclass."""

    def test_default_values(self):
        """Test default values."""
        func = FunctionNode(name="transfer", visibility=Visibility.PUBLIC)
        assert func.name == "transfer"
        assert func.visibility == Visibility.PUBLIC
        assert func.mutability == Mutability.NONPAYABLE
        assert func.modifiers == []
        assert func.parameters == []
        assert func.returns == []
        assert func.state_vars_read == set()
        assert func.state_vars_written == set()
        assert func.internal_calls == []
        assert func.external_calls == []
        assert func.start_line == 0
        assert func.end_line == 0
        assert func.is_constructor is False
        assert func.is_fallback is False
        assert func.is_receive is False
        assert func.has_reentrancy_guard is False
        assert func.has_access_control is False

    def test_is_entry_point_external(self):
        """Test is_entry_point for external visibility."""
        func = FunctionNode(name="withdraw", visibility=Visibility.EXTERNAL)
        assert func.is_entry_point is True

    def test_is_entry_point_public(self):
        """Test is_entry_point for public visibility."""
        func = FunctionNode(name="transfer", visibility=Visibility.PUBLIC)
        assert func.is_entry_point is True

    def test_is_entry_point_internal(self):
        """Test is_entry_point for internal visibility."""
        func = FunctionNode(name="_update", visibility=Visibility.INTERNAL)
        assert func.is_entry_point is False

    def test_is_entry_point_private(self):
        """Test is_entry_point for private visibility."""
        func = FunctionNode(name="_helper", visibility=Visibility.PRIVATE)
        assert func.is_entry_point is False

    def test_is_payable(self):
        """Test is_payable property."""
        payable = FunctionNode(
            name="deposit",
            visibility=Visibility.PUBLIC,
            mutability=Mutability.PAYABLE,
        )
        assert payable.is_payable is True

        nonpayable = FunctionNode(
            name="withdraw",
            visibility=Visibility.PUBLIC,
            mutability=Mutability.NONPAYABLE,
        )
        assert nonpayable.is_payable is False

    def test_modifies_state(self):
        """Test modifies_state property."""
        func_writes = FunctionNode(
            name="update",
            visibility=Visibility.PUBLIC,
            state_vars_written={"balance"},
        )
        assert func_writes.modifies_state is True

        func_no_writes = FunctionNode(
            name="view",
            visibility=Visibility.PUBLIC,
            state_vars_written=set(),
        )
        assert func_no_writes.modifies_state is False

    def test_makes_external_calls(self):
        """Test makes_external_calls property."""
        func_with_calls = FunctionNode(
            name="withdraw",
            visibility=Visibility.PUBLIC,
            external_calls=["target.call"],
        )
        assert func_with_calls.makes_external_calls is True

        func_no_calls = FunctionNode(
            name="deposit",
            visibility=Visibility.PUBLIC,
            external_calls=[],
        )
        assert func_no_calls.makes_external_calls is False

    def test_to_dict(self):
        """Test to_dict method."""
        func = FunctionNode(
            name="transfer",
            visibility=Visibility.PUBLIC,
            mutability=Mutability.NONPAYABLE,
            modifiers=["onlyOwner"],
            parameters=["address to", "uint256 amount"],
            returns=["bool"],
            state_vars_read={"balance"},
            state_vars_written={"balance"},
            internal_calls=["_update"],
            external_calls=["token.transfer"],
            start_line=10,
            end_line=20,
            has_reentrancy_guard=True,
            has_access_control=True,
        )

        d = func.to_dict()
        assert d["name"] == "transfer"
        assert d["visibility"] == "public"
        assert d["mutability"] == "nonpayable"
        assert d["modifiers"] == ["onlyOwner"]
        assert d["is_entry_point"] is True
        assert d["is_payable"] is False
        assert d["modifies_state"] is True
        assert d["makes_external_calls"] is True
        assert d["has_reentrancy_guard"] is True
        assert d["has_access_control"] is True
        assert d["location"]["start"] == 10
        assert d["location"]["end"] == 20


class TestCallEdge:
    """Tests for CallEdge dataclass."""

    def test_creation(self):
        """Test edge creation."""
        edge = CallEdge(caller="withdraw", callee="_update", call_type="internal")
        assert edge.caller == "withdraw"
        assert edge.callee == "_update"
        assert edge.call_type == "internal"
        assert edge.line == 0

    def test_with_line(self):
        """Test edge with line number."""
        edge = CallEdge(
            caller="withdraw",
            callee="target.call",
            call_type="external",
            line=42,
        )
        assert edge.line == 42

    def test_to_dict(self):
        """Test to_dict method."""
        edge = CallEdge(
            caller="transfer",
            callee="recipient.call",
            call_type="call",
            line=50,
        )
        d = edge.to_dict()
        assert d["caller"] == "transfer"
        assert d["callee"] == "recipient.call"
        assert d["type"] == "call"
        assert d["line"] == 50


class TestCallPath:
    """Tests for CallPath dataclass."""

    def test_creation(self):
        """Test path creation."""
        path = CallPath(
            nodes=["withdraw", "_update", "_send"],
            edges=[],
        )
        assert path.nodes == ["withdraw", "_update", "_send"]
        assert path.has_external_call is False
        assert path.has_state_modification is False

    def test_length(self):
        """Test length property."""
        path = CallPath(nodes=["a", "b", "c"], edges=[])
        assert path.length == 3

    def test_with_flags(self):
        """Test path with flags."""
        path = CallPath(
            nodes=["withdraw"],
            edges=[],
            has_external_call=True,
            has_state_modification=True,
        )
        assert path.has_external_call is True
        assert path.has_state_modification is True

    def test_to_dict(self):
        """Test to_dict method."""
        path = CallPath(
            nodes=["a", "b"],
            edges=[],
            has_external_call=True,
            has_state_modification=False,
        )
        d = path.to_dict()
        assert d["path"] == ["a", "b"]
        assert d["length"] == 2
        assert d["has_external_call"] is True
        assert d["has_state_modification"] is False


class TestCallGraph:
    """Tests for CallGraph class."""

    @pytest.fixture
    def empty_graph(self):
        """Create empty call graph."""
        return CallGraph("TestContract")

    @pytest.fixture
    def simple_graph(self):
        """Create simple call graph."""
        graph = CallGraph("SimpleContract")

        # Add functions
        withdraw = FunctionNode(
            name="withdraw",
            visibility=Visibility.EXTERNAL,
            state_vars_written={"balance"},
            external_calls=["msg.sender.call"],
        )
        update = FunctionNode(name="_update", visibility=Visibility.INTERNAL)
        graph.add_function(withdraw)
        graph.add_function(update)

        # Add edge
        graph.add_edge(CallEdge("withdraw", "_update", "internal"))

        return graph

    def test_init(self, empty_graph):
        """Test initialization."""
        assert empty_graph.contract_name == "TestContract"
        assert empty_graph.nodes == {}
        assert empty_graph.edges == []

    def test_dangerous_sinks_defined(self):
        """Test DANGEROUS_SINKS is properly defined."""
        assert "call" in CallGraph.DANGEROUS_SINKS
        assert "delegatecall" in CallGraph.DANGEROUS_SINKS
        assert "selfdestruct" in CallGraph.DANGEROUS_SINKS

    def test_access_control_modifiers_defined(self):
        """Test ACCESS_CONTROL_MODIFIERS is properly defined."""
        assert "onlyOwner" in CallGraph.ACCESS_CONTROL_MODIFIERS
        assert "onlyAdmin" in CallGraph.ACCESS_CONTROL_MODIFIERS

    def test_reentrancy_guard_modifiers_defined(self):
        """Test REENTRANCY_GUARD_MODIFIERS is properly defined."""
        assert "nonReentrant" in CallGraph.REENTRANCY_GUARD_MODIFIERS
        assert "lock" in CallGraph.REENTRANCY_GUARD_MODIFIERS

    def test_add_function(self, empty_graph):
        """Test adding a function."""
        func = FunctionNode(name="test", visibility=Visibility.PUBLIC)
        empty_graph.add_function(func)
        assert "test" in empty_graph.nodes

    def test_add_edge(self, empty_graph):
        """Test adding an edge."""
        edge = CallEdge("a", "b", "internal")
        empty_graph.add_edge(edge)
        assert len(empty_graph.edges) == 1
        assert "b" in empty_graph._adjacency["a"]
        assert "a" in empty_graph._reverse_adjacency["b"]

    def test_get_entry_points(self, simple_graph):
        """Test getting entry points."""
        entry_points = simple_graph.get_entry_points()
        assert len(entry_points) == 1
        assert entry_points[0].name == "withdraw"

    def test_get_callees(self, simple_graph):
        """Test getting callees."""
        callees = simple_graph.get_callees("withdraw")
        assert "_update" in callees

    def test_get_callees_nonexistent(self, simple_graph):
        """Test getting callees for nonexistent function."""
        callees = simple_graph.get_callees("nonexistent")
        assert callees == []

    def test_get_callers(self, simple_graph):
        """Test getting callers."""
        callers = simple_graph.get_callers("_update")
        assert "withdraw" in callers

    def test_get_callers_nonexistent(self, simple_graph):
        """Test getting callers for nonexistent function."""
        callers = simple_graph.get_callers("nonexistent")
        assert callers == []

    def test_reachable_from(self):
        """Test reachable_from BFS."""
        graph = CallGraph("Test")
        graph.add_function(FunctionNode(name="a", visibility=Visibility.PUBLIC))
        graph.add_function(FunctionNode(name="b", visibility=Visibility.INTERNAL))
        graph.add_function(FunctionNode(name="c", visibility=Visibility.INTERNAL))
        graph.add_edge(CallEdge("a", "b", "internal"))
        graph.add_edge(CallEdge("b", "c", "internal"))

        reachable = graph.reachable_from("a")
        assert "a" in reachable
        assert "b" in reachable
        assert "c" in reachable

    def test_reachable_from_nonexistent(self, empty_graph):
        """Test reachable_from with nonexistent function."""
        reachable = empty_graph.reachable_from("nonexistent")
        assert reachable == set()

    def test_can_reach(self):
        """Test can_reach method."""
        graph = CallGraph("Test")
        graph.add_function(FunctionNode(name="a", visibility=Visibility.PUBLIC))
        graph.add_function(FunctionNode(name="b", visibility=Visibility.INTERNAL))
        graph.add_edge(CallEdge("a", "b", "internal"))

        assert graph.can_reach("a", "b") is True
        assert graph.can_reach("b", "a") is False

    def test_paths_to_sink(self):
        """Test finding paths to sink."""
        graph = CallGraph("Test")
        graph.add_function(FunctionNode(name="entry", visibility=Visibility.PUBLIC))
        graph.add_function(FunctionNode(name="middle", visibility=Visibility.INTERNAL))
        graph.add_function(FunctionNode(name="sink", visibility=Visibility.INTERNAL))
        graph.add_edge(CallEdge("entry", "middle", "internal"))
        graph.add_edge(CallEdge("middle", "sink", "internal"))

        paths = graph.paths_to_sink("sink")
        assert len(paths) == 1
        assert paths[0].nodes == ["entry", "middle", "sink"]

    def test_paths_to_sink_no_path(self, empty_graph):
        """Test paths_to_sink with no paths."""
        paths = empty_graph.paths_to_sink("nonexistent")
        assert paths == []

    def test_external_call_chains_direct(self):
        """Test external call chains with direct entry point."""
        graph = CallGraph("Test")
        func = FunctionNode(
            name="withdraw",
            visibility=Visibility.EXTERNAL,
            external_calls=["target.call"],
            state_vars_written={"balance"},
        )
        graph.add_function(func)

        chains = graph.external_call_chains()
        assert len(chains) == 1
        assert chains[0].has_external_call is True

    def test_external_call_chains_indirect(self):
        """Test external call chains with indirect path."""
        graph = CallGraph("Test")
        entry = FunctionNode(name="entry", visibility=Visibility.PUBLIC)
        inner = FunctionNode(
            name="inner",
            visibility=Visibility.INTERNAL,
            external_calls=["target.call"],
        )
        graph.add_function(entry)
        graph.add_function(inner)
        graph.add_edge(CallEdge("entry", "inner", "internal"))

        chains = graph.external_call_chains()
        assert len(chains) >= 1

    def test_get_reentrancy_risk_paths(self):
        """Test getting reentrancy risk paths."""
        graph = CallGraph("Test")
        func = FunctionNode(
            name="withdraw",
            visibility=Visibility.EXTERNAL,
            external_calls=["target.call"],
            state_vars_written={"balance"},
            has_reentrancy_guard=False,
        )
        graph.add_function(func)

        risky = graph.get_reentrancy_risk_paths()
        assert len(risky) >= 1

    def test_get_reentrancy_risk_paths_with_guard(self):
        """Test that guarded functions are not risky."""
        graph = CallGraph("Test")
        func = FunctionNode(
            name="withdraw",
            visibility=Visibility.EXTERNAL,
            external_calls=["target.call"],
            state_vars_written={"balance"},
            has_reentrancy_guard=True,
        )
        graph.add_function(func)

        risky = graph.get_reentrancy_risk_paths()
        assert len(risky) == 0

    def test_get_unprotected_state_modifiers(self):
        """Test getting unprotected state modifiers."""
        graph = CallGraph("Test")
        func = FunctionNode(
            name="setOwner",
            visibility=Visibility.PUBLIC,
            state_vars_written={"owner"},
            has_access_control=False,
        )
        graph.add_function(func)

        unprotected = graph.get_unprotected_state_modifiers()
        assert len(unprotected) == 1
        assert unprotected[0].name == "setOwner"

    def test_get_unprotected_excludes_constructors(self):
        """Test that constructors are excluded from unprotected."""
        graph = CallGraph("Test")
        func = FunctionNode(
            name="constructor",
            visibility=Visibility.PUBLIC,
            state_vars_written={"owner"},
            has_access_control=False,
            is_constructor=True,
        )
        graph.add_function(func)

        unprotected = graph.get_unprotected_state_modifiers()
        assert len(unprotected) == 0

    def test_get_unprotected_excludes_underscore(self):
        """Test that _prefixed functions are excluded."""
        graph = CallGraph("Test")
        func = FunctionNode(
            name="_internal",
            visibility=Visibility.PUBLIC,
            state_vars_written={"data"},
            has_access_control=False,
        )
        graph.add_function(func)

        unprotected = graph.get_unprotected_state_modifiers()
        assert len(unprotected) == 0

    def test_get_summary(self, simple_graph):
        """Test get_summary method."""
        summary = simple_graph.get_summary()
        assert summary["contract"] == "SimpleContract"
        assert summary["total_functions"] == 2
        assert summary["entry_points"] == 1
        assert "external_call_chains" in summary
        assert "reentrancy_risk_paths" in summary

    def test_to_dict(self, simple_graph):
        """Test to_dict method."""
        d = simple_graph.to_dict()
        assert d["contract"] == "SimpleContract"
        assert "withdraw" in d["nodes"]
        assert "_update" in d["nodes"]
        assert len(d["edges"]) == 1
        assert "summary" in d


class TestCallGraphBuilder:
    """Tests for CallGraphBuilder class."""

    @pytest.fixture
    def builder(self):
        """Create builder instance."""
        return CallGraphBuilder()

    def test_init(self, builder):
        """Test initialization."""
        assert builder is not None

    def test_build_from_source_simple(self, builder):
        """Test building from simple source code."""
        source = """
        contract Test {
            uint256 public balance;

            function deposit() public payable {
                balance += msg.value;
            }

            function withdraw() external {
                balance = 0;
                msg.sender.call{value: balance}("");
            }
        }
        """
        graph = builder.build_from_source(source, "Test")
        assert graph.contract_name == "Test"
        assert "deposit" in graph.nodes
        assert "withdraw" in graph.nodes

    def test_build_from_source_visibility(self, builder):
        """Test visibility parsing."""
        source = """
        contract Test {
            function pubFunc() public {}
            function extFunc() external {}
            function intFunc() internal {}
            function privFunc() private {}
        }
        """
        graph = builder.build_from_source(source, "Test")

        assert graph.nodes["pubFunc"].visibility == Visibility.PUBLIC
        assert graph.nodes["extFunc"].visibility == Visibility.EXTERNAL
        assert graph.nodes["intFunc"].visibility == Visibility.INTERNAL
        assert graph.nodes["privFunc"].visibility == Visibility.PRIVATE

    def test_build_from_source_mutability(self, builder):
        """Test mutability parsing."""
        source = """
        contract Test {
            function payableFunc() public payable {}
            function viewFunc() public view returns (uint) {}
            function pureFunc() public pure returns (uint) {}
        }
        """
        graph = builder.build_from_source(source, "Test")

        assert graph.nodes["payableFunc"].mutability == Mutability.PAYABLE
        assert graph.nodes["viewFunc"].mutability == Mutability.VIEW
        assert graph.nodes["pureFunc"].mutability == Mutability.PURE

    def test_build_from_source_with_modifiers(self, builder):
        """Test modifier detection."""
        source = """
        contract Test {
            function protectedFunc() public onlyOwner nonReentrant {
            }
        }
        """
        graph = builder.build_from_source(source, "Test")
        func = graph.nodes.get("protectedFunc")
        if func:
            assert func.has_access_control is True
            assert func.has_reentrancy_guard is True

    def test_build_from_slither_empty(self, builder):
        """Test building from empty Slither output."""
        slither_output = {}
        graph = builder.build_from_slither(slither_output)
        assert graph.contract_name == "Contract"
        assert len(graph.nodes) == 0

    def test_build_from_slither_with_printers(self, builder):
        """Test building from Slither with printers."""
        slither_output = {
            "results": {
                "printers": [
                    {
                        "printer": "call-graph",
                        "elements": [
                            {"type": "function", "name": "transfer"},
                            {"type": "function", "name": "withdraw"},
                            {
                                "type": "edge",
                                "source": "transfer",
                                "target": "withdraw",
                            },
                        ],
                    }
                ]
            }
        }
        graph = builder.build_from_slither(slither_output)
        assert "transfer" in graph.nodes
        assert "withdraw" in graph.nodes
        assert len(graph.edges) == 1

    def test_build_from_slither_with_visibility(self, builder):
        """Test visibility extraction from Slither."""
        slither_output = {
            "results": {
                "printers": [
                    {
                        "printer": "call-graph",
                        "elements": [
                            {
                                "type": "function",
                                "name": "withdraw",
                                "additional_fields": {"visibility": "external"},
                            },
                        ],
                    }
                ]
            }
        }
        graph = builder.build_from_slither(slither_output)
        assert graph.nodes["withdraw"].visibility == Visibility.EXTERNAL

    def test_build_from_slither_detectors(self, builder):
        """Test building from Slither detectors when no call-graph printer."""
        slither_output = {
            "results": {
                "detectors": [
                    {
                        "elements": [
                            {
                                "type": "function",
                                "name": "vulnerable",
                                "type_specific_fields": {"visibility": "public"},
                            }
                        ]
                    }
                ]
            }
        }
        graph = builder.build_from_slither(slither_output)
        assert "vulnerable" in graph.nodes

    def test_extract_calls_from_source(self, builder):
        """Test call extraction from source."""
        source = """
        contract Test {
            function withdraw() public {
                target.call("");
                recipient.transfer(100);
            }
        }
        """
        graph = builder.build_from_source(source, "Test")
        func = graph.nodes.get("withdraw")
        if func:
            assert len(func.external_calls) >= 1


class TestConvenienceFunctions:
    """Tests for convenience functions."""

    def test_build_call_graph(self):
        """Test build_call_graph function."""
        source = """
        contract Test {
            function deposit() public payable {}
        }
        """
        graph = build_call_graph(source, "Test")
        assert graph.contract_name == "Test"
        assert "deposit" in graph.nodes

    def test_analyze_reentrancy_risk(self):
        """Test analyze_reentrancy_risk function."""
        source = """
        contract Test {
            uint balance;
            function withdraw() public {
                balance = 0;
                msg.sender.call{value: balance}("");
            }
        }
        """
        result = analyze_reentrancy_risk(source)
        assert "risky_paths_count" in result
        assert "risky_paths" in result
        assert "summary" in result


class TestEdgeCases:
    """Edge case tests."""

    def test_cyclic_calls(self):
        """Test handling of cyclic call graphs."""
        graph = CallGraph("Test")
        graph.add_function(FunctionNode(name="a", visibility=Visibility.PUBLIC))
        graph.add_function(FunctionNode(name="b", visibility=Visibility.INTERNAL))
        graph.add_edge(CallEdge("a", "b", "internal"))
        graph.add_edge(CallEdge("b", "a", "internal"))  # Cycle

        # Should not hang
        reachable = graph.reachable_from("a")
        assert "a" in reachable
        assert "b" in reachable

    def test_self_call(self):
        """Test handling of self-recursive calls."""
        graph = CallGraph("Test")
        graph.add_function(FunctionNode(name="recursive", visibility=Visibility.PUBLIC))
        graph.add_edge(CallEdge("recursive", "recursive", "internal"))

        # Should not hang
        reachable = graph.reachable_from("recursive")
        assert "recursive" in reachable

    def test_disconnected_graph(self):
        """Test graph with disconnected components."""
        graph = CallGraph("Test")
        graph.add_function(FunctionNode(name="a", visibility=Visibility.PUBLIC))
        graph.add_function(FunctionNode(name="b", visibility=Visibility.PUBLIC))
        # No edges

        reachable_a = graph.reachable_from("a")
        reachable_b = graph.reachable_from("b")

        assert reachable_a == {"a"}
        assert reachable_b == {"b"}

    def test_max_depth_limiting(self):
        """Test that max_depth limits path search."""
        graph = CallGraph("Test")
        # Create a long chain
        for i in range(20):
            vis = Visibility.PUBLIC if i == 0 else Visibility.INTERNAL
            graph.add_function(FunctionNode(name=f"f{i}", visibility=vis))
            if i > 0:
                graph.add_edge(CallEdge(f"f{i-1}", f"f{i}", "internal"))

        paths = graph.paths_to_sink("f15", max_depth=5)
        # Should not find path because it's too long
        assert len(paths) == 0

    def test_empty_function_name(self):
        """Test handling of empty function names."""
        graph = CallGraph("Test")
        graph.add_function(FunctionNode(name="", visibility=Visibility.PUBLIC))
        assert "" in graph.nodes

    def test_special_characters_in_source(self):
        """Test parsing source with special characters."""
        source = """
        contract Test {
            // Comment with special chars: <>&
            function test() public {
                /* Multi-line
                   comment */
            }
        }
        """
        builder = CallGraphBuilder()
        graph = builder.build_from_source(source)
        # Should not crash
        assert graph is not None
