import os, json, time, base64, hmac, hashlib
from flask import Flask, request, jsonify, redirect, url_for
from models import (
    Document,
    DocumentRevision,
    User,
    Role,
    UserRole,
    get_session,
)

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "dev")

ONLYOFFICE_INTERNAL_URL = os.environ["ONLYOFFICE_INTERNAL_URL"]  # http://onlyoffice
ONLYOFFICE_PUBLIC_URL   = os.environ["ONLYOFFICE_PUBLIC_URL"]    # https://qdms.example.com/onlyoffice
ONLYOFFICE_JWT_SECRET   = os.environ["ONLYOFFICE_JWT_SECRET"]
ONLYOFFICE_JWT_HEADER   = os.environ.get("ONLYOFFICE_JWT_HEADER", "AuthorizationJwt")

# Demo: örnek bir dokümanı MinIO'ya kaydettiğinizi varsayın ve anahtarını (storage key) biliyorsunuz:
def sign_payload(payload: dict) -> str:
    # OnlyOffice JWT payload (HS256)
    header = {"alg":"HS256","typ":"JWT"}
    def b64(x): return base64.urlsafe_b64encode(json.dumps(x, separators=(',',':')).encode()).rstrip(b'=')
    segs = [b64(header), b64(payload)]
    sig = hmac.new(ONLYOFFICE_JWT_SECRET.encode(), b'.'.join(segs), hashlib.sha256).digest()
    segs.append(base64.urlsafe_b64encode(sig).rstrip(b'='))
    return b'.'.join(segs).decode()

@app.route("/")
def index():
    return jsonify(ok=True, msg="QDMS Portal running")


@app.post("/roles/assign")
def assign_role():
    """Assign a role to a user."""
    data = request.get_json(silent=True) or {}
    user_id = data.get("user_id")
    role_name = data.get("role")
    if not user_id or not role_name:
        return jsonify(error="user_id and role required"), 400
    session = get_session()
    try:
        user = session.get(User, user_id)
        if not user:
            user = User(id=user_id, username=data.get("username", str(user_id)), email=data.get("email"))
            session.add(user)
            session.commit()
        role = session.query(Role).filter_by(name=role_name).first()
        if not role:
            role = Role(name=role_name)
            session.add(role)
            session.commit()
        link = session.query(UserRole).filter_by(user_id=user.id, role_id=role.id).first()
        if not link:
            session.add(UserRole(user_id=user.id, role_id=role.id))
        session.commit()
        return jsonify(ok=True)
    finally:
        session.close()

@app.route("/doc/<doc_key>/edit")
def edit(doc_key):
    # doc_key: MinIO’daki dosya anahtarınız (örn: qdms/PRO-001_v1.docx)
    user = {"id":"u1","name":"Ibrahim H.","email":"ih@baylan.local"}
    # OnlyOffice editor config (minimal)
    config = {
      "document": {
        "fileType": "docx",
        "key": f"{doc_key}",  # versiyon anahtarı; revizyon değişince değiştirin
        "title": f"{doc_key.split('/')[-1]}",
        "url": f"{os.environ['S3_ENDPOINT']}/local/{doc_key}",  # demo (gerçekte imzalı URL üretin)
        "permissions": {
          "edit": True,
          "download": True,
          "review": True,
          "comment": True
        }
      },
      "documentType": "text",
      "editorConfig": {
        "callbackUrl": f"{os.environ['PORTAL_PUBLIC_BASE_URL']}/onlyoffice/callback/{doc_key}",
        "user": {"id":user["id"], "name":user["name"]},
        "mode": "edit"
      }
    }
    token = sign_payload(config)
    # İstemci tarafta OnlyOffice Editor’ü çağırırken bu token’ı gönderirsiniz.
    return jsonify(
      editor_js=f"{ONLYOFFICE_PUBLIC_URL}/web-apps/apps/api/documents/api.js",
      config=config,
      token=token,
      token_header=ONLYOFFICE_JWT_HEADER
    )

@app.post("/documents/<int:doc_id>/revision")
def save_revision(doc_id):
    session = get_session()
    data = request.get_json(silent=True) or {}
    track_changes = data.get("track_changes")
    compare_result = data.get("compare_result")
    revision_notes = data.get("revision_notes")
    doc = session.get(Document, doc_id)
    if not doc:
        session.close()
        return jsonify(error="document not found"), 404
    doc.minor_version += 1
    doc.revision_notes = revision_notes
    rev = DocumentRevision(
        doc_id=doc.id,
        major_version=doc.major_version,
        minor_version=doc.minor_version,
        revision_notes=revision_notes,
        track_changes=track_changes,
        compare_result=compare_result,
    )
    session.add(rev)
    session.commit()
    session.close()
    return jsonify(ok=True, version=f"{doc.major_version}.{doc.minor_version}")

@app.post("/onlyoffice/callback/<path:doc_key>")
def onlyoffice_callback(doc_key):
    data = request.get_json(silent=True) or {}
    status = data.get("status")
    # status 2 veya 6 → dosya kapandı/kaydedildi; data['url'] ile final içeriği çekilebilir
    # Burada yeni versiyon yaratıp MinIO’ya yazarsınız; audit-log tutarsınız.
    # Güvenlik için Header’daki JWT’yi doğrulayın (OnlyOffice config -> JWT).
    return jsonify(error=0)


if __name__ == "__main__":
    bind = os.environ.get("BIND", "0.0.0.0:5000")
    host, port = bind.split(":")
    debug = os.environ.get("DEBUG", "").lower() in {"1", "true", "yes"}
    app.run(host=host, port=int(port), debug=debug)
