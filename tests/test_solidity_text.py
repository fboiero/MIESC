"""Unit tests for the shared index-preserving Solidity text helpers."""

from miesc.llm._solidity_text import _line_of, _match_brace, _strip_comments


class TestStripComments:
    def test_line_comment_blanked_to_eol_rest_kept(self):
        src = "uint x = 1; // set x\nuint y = 2;"
        out = _strip_comments(src)
        assert out.startswith("uint x = 1; ")
        assert "set x" not in out
        assert "uint y = 2;" in out

    def test_block_comment_spanning_lines_preserves_newlines(self):
        src = "a;\n/* c1\nc2 */\nb;"
        out = _strip_comments(src)
        # indexes and line count are preserved; the comment text is gone
        assert len(out) == len(src)
        assert out.count("\n") == src.count("\n")
        assert "c1" not in out and "c2" not in out
        assert "a;" in out and "b;" in out

    def test_unterminated_block_comment_does_not_crash(self):
        out = _strip_comments("x;\n/* never closed")
        assert len(out) == len("x;\n/* never closed")
        assert "never closed" not in out

    def test_string_bodies_are_not_tracked(self):
        # documented heuristic: a // inside a string is blanked too
        out = _strip_comments('string u = "http://x"; // real')
        assert "real" not in out  # the trailing comment is gone
        assert "//x" not in out  # the in-string // was also blanked
        assert len(out) == len('string u = "http://x"; // real')

    def test_length_is_always_preserved(self):
        for src in ("", "no comments here", "a//b", "/**/", "/*\n*/"):
            assert len(_strip_comments(src)) == len(src)


class TestLineOf:
    def test_index_zero_is_line_one(self):
        assert _line_of("abc", 0) == 1

    def test_counts_newlines_before_index(self):
        src = "a\nb\nc"
        assert _line_of(src, src.index("c")) == 3


class TestMatchBrace:
    def test_nested_braces(self):
        src = "f() { if (x) { g(); } }"
        open_idx = src.index("{")
        close = _match_brace(src, open_idx)
        assert src[close] == "}"
        assert close == len(src) - 1  # the outer closing brace

    def test_unmatched_returns_len(self):
        src = "f() { g();"
        assert _match_brace(src, src.index("{")) == len(src)


class TestMaskStrings:
    def test_blanks_string_contents_and_keeps_offsets(self):
        from miesc.llm._solidity_text import _mask_strings

        src = "require(ok, \"for bonded amount\"); x = 'a{b'; // for\n"
        out = _mask_strings(src)
        assert len(out) == len(src)
        assert "for bonded" not in out and "a{b" not in out
        assert out.startswith('require(ok, "') and out.count('"') == 2
        # the comment is not a string: untouched here (comments are a separate pass)
        assert out.endswith("// for\n")

    def test_escaped_quote_does_not_end_the_literal(self):
        from miesc.llm._solidity_text import _mask_strings

        src = 'emit E("say \\"for\\" now"); for (;;) {}'
        out = _mask_strings(src)
        assert "for (;;)" in out and "say" not in out


class TestBodyBrace:
    def test_returns_the_opening_brace_of_a_body(self):
        from miesc.llm._solidity_text import _body_brace

        src = "function f() public returns (uint) { return 1; }"
        assert src[_body_brace(src, src.index(")") + 1)] == "{"

    def test_bodiless_declaration_returns_minus_one(self):
        from miesc.llm._solidity_text import _body_brace

        src = "function execute(address to) external;\ncontract W { function g() { } }"
        assert _body_brace(src, src.index(")") + 1) == -1

    def test_no_brace_at_all_returns_minus_one(self):
        from miesc.llm._solidity_text import _body_brace

        assert _body_brace("function f() external", 12) == -1
