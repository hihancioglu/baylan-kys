import hashlib, os, json

SRC_DIR = 'src'
DIST_DIR = 'dist'

def minify(content):
    return ''.join(line.strip() for line in content.splitlines())

def build_file(name):
    with open(os.path.join(SRC_DIR, name)) as f:
        content = f.read()
    minified = minify(content)
    digest = hashlib.md5(minified.encode()).hexdigest()[:8]
    base, ext = os.path.splitext(name)
    out_name = f"{base}-{digest}{ext}"
    with open(os.path.join(DIST_DIR, out_name), 'w') as f:
        f.write(minified)
    return name, out_name

if __name__ == '__main__':
    os.makedirs(DIST_DIR, exist_ok=True)
    manifest = {}
    for fname in ['app.css', 'app.js']:
        key, out = build_file(fname)
        manifest[key] = out
    with open(os.path.join(DIST_DIR, 'manifest.json'), 'w') as f:
        json.dump(manifest, f, indent=2)
