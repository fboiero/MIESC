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
