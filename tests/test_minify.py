import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from portal.static.build import minify


def test_minify_removes_single_line_comments():
    content = """
// File-level comment
const a = 1; // trailing comment
const url = "http://example.com"; // keep url
"""
    assert (
        minify(content)
        == 'const a = 1;const url = "http://example.com";'
    )

