import os, json, time, base64, hmac, hashlib
from flask import Flask, request, jsonify, redirect, url_for

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

@app.post("/onlyoffice/callback/<path:doc_key>")
def onlyoffice_callback(doc_key):
    data = request.get_json(silent=True) or {}
    status = data.get("status")
    # status 2 veya 6 → dosya kapandı/kaydedildi; data['url'] ile final içeriği çekilebilir
    # Burada yeni versiyon yaratıp MinIO’ya yazarsınız; audit-log tutarsınız.
    # Güvenlik için Header’daki JWT’yi doğrulayın (OnlyOffice config -> JWT).
    return jsonify(error=0)
