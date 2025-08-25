import os, re

BASE_DIR = os.path.join(os.path.dirname(__file__), 'static')
SRC_DIR = os.path.join(BASE_DIR, 'src')
# Write minified assets into a dedicated ``static-dist`` directory. This
# directory is mounted as a shared volume between the portal and nginx
# containers so both can access the generated files.
DEST_DIR = os.path.join(os.path.dirname(__file__), 'static-dist')

def minify(content):
    """Basic minifier for JS/CSS files.

    Removes single-line ``//`` comments before collapsing whitespace and
    newlines so that code following a comment does not become commented out.
    This is a very small utility and intentionally simple; it does not handle
    complex cases such as block comments or ``//`` appearing inside strings
    without surrounding quotes.
    """

    lines = []
    for line in content.splitlines():
        # Strip trailing single-line comments. This looks for ``//`` preceded by
        # whitespace to avoid removing protocol references like ``http://``.
        line = re.sub(r"\s+//.*", "", line)
        stripped = line.strip()
        # Skip lines that are solely comments.
        if stripped.startswith("//") or stripped == "":
            continue
        lines.append(stripped)
    return ''.join(lines)

def build_file(src_path, rel_path):
    with open(src_path) as f:
        content = f.read()
    minified = minify(content)
    out_full = os.path.join(DEST_DIR, rel_path)
    os.makedirs(os.path.dirname(out_full), exist_ok=True)
    with open(out_full, 'w') as f:
        f.write(minified)

if __name__ == '__main__':
    os.makedirs(DEST_DIR, exist_ok=True)
    for root, _, files in os.walk(SRC_DIR):
        rel_dir = os.path.relpath(root, SRC_DIR)
        for fname in files:
            if fname.endswith(('.css', '.js')):
                rel_path = fname if rel_dir == '.' else os.path.join(rel_dir, fname)
                build_file(os.path.join(root, fname), rel_path)
