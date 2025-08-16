import hashlib, os, json

SRC_DIR = 'src'
DIST_DIR = 'dist'

def minify(content):
    return ''.join(line.strip() for line in content.splitlines())

def build_file(src_path, rel_path, hash_name):
    with open(src_path) as f:
        content = f.read()
    minified = minify(content)
    if hash_name:
        digest = hashlib.md5(minified.encode()).hexdigest()[:8]
        base, ext = os.path.splitext(rel_path)
        out_rel = f"{base}-{digest}{ext}"
    else:
        out_rel = rel_path
    out_full = os.path.join(DIST_DIR, out_rel)
    os.makedirs(os.path.dirname(out_full), exist_ok=True)
    with open(out_full, 'w') as f:
        f.write(minified)
    return rel_path, out_rel

if __name__ == '__main__':
    os.makedirs(DIST_DIR, exist_ok=True)
    manifest = {}
    for root, _, files in os.walk(SRC_DIR):
        rel_dir = os.path.relpath(root, SRC_DIR)
        for fname in files:
            if fname.endswith(('.css', '.js')):
                rel_path = fname if rel_dir == '.' else os.path.join(rel_dir, fname)
                hash_name = rel_dir == '.' and fname != 'tokens.js'
                key, out_rel = build_file(os.path.join(root, fname), rel_path, hash_name)
                manifest[key] = out_rel
    with open(os.path.join(DIST_DIR, 'manifest.json'), 'w') as f:
        json.dump(manifest, f, indent=2)
