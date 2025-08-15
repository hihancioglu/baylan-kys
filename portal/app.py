import os, json, time, base64, hmac, hashlib, csv, io
from flask import Flask, request, jsonify, redirect, url_for, render_template, Response
from models import (
    Document,
    DocumentRevision,
    User,
    Role,
    UserRole,
    Acknowledgement,
    TrainingResult,
    FormSubmission,
    ChangeRequest,
    Deviation,
    CAPAAction,
    AuditLog,
    NotificationSetting,
    get_session,
)
from search import index_document, search_documents
from ocr import extract_text
from docxf_render import render_form_to_pdf
from notifications import notify_revision_time, notify_mandatory_read
from reports import (
    build_report,
    revision_report,
    training_compliance_report,
    pending_approvals_report,
)
from signing import create_signed_pdf

app = Flask(__name__, static_folder="static/dist")
app.secret_key = os.environ.get("SECRET_KEY", "dev")

manifest_path = os.path.join(app.static_folder, "manifest.json")
if os.path.exists(manifest_path):
    with open(manifest_path) as f:
        _asset_manifest = json.load(f)
else:
    _asset_manifest = {}


def asset_url(name: str) -> str:
    filename = _asset_manifest.get(name, name)
    return url_for("static", filename=filename)


app.jinja_env.globals["asset_url"] = asset_url

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


def log_action(user_id, doc_id, action):
    """Persist an audit log entry."""
    session = get_session()
    try:
        session.add(AuditLog(user_id=user_id, doc_id=doc_id, action=action))
        session.commit()
    finally:
        session.close()

@app.route("/")
def index():
    return render_template("index.html")


@app.get("/health")
def health():
    return jsonify(status="ok")


@app.get("/archive")
def list_archived_documents():
    session = get_session()
    docs = session.query(Document).filter_by(status="Archived").all()
    result = [
        {
            "id": d.id,
            "doc_key": d.doc_key,
            "title": d.title,
            "archived_at": d.archived_at.isoformat() if d.archived_at else None,
        }
        for d in docs
    ]
    session.close()
    return jsonify(result)


@app.post("/documents")
def create_document():
    data = request.get_json(silent=True) or {}
    doc = Document(
        doc_key=data.get("doc_key"),
        title=data.get("title"),
        code=data.get("code"),
        tags=",".join(data.get("tags", [])) if isinstance(data.get("tags"), list) else data.get("tags"),
        department=data.get("department"),
        process=data.get("process"),
        retention_period=data.get("retention_period"),
    )
    session = get_session()
    session.add(doc)
    session.commit()
    log_action(data.get("user_id"), doc.id, "create_document")
    content = ""
    if data.get("file_path"):
        content = extract_text(data["file_path"])
    index_document(doc, content)
    user_ids = [u.id for u in session.query(User).all()]
    notify_mandatory_read(doc, user_ids)
    result = {"id": doc.id}
    session.close()
    return jsonify(result), 201


@app.post("/documents/<int:doc_id>/sign")
def sign_document(doc_id: int):
    data = request.get_json(silent=True) or {}
    user_id = data.get("user_id")
    file_path = data.get("file_path")
    if not user_id or not file_path:
        return jsonify(error="user_id and file_path required"), 400
    try:
        signed_pdf = create_signed_pdf(doc_id, user_id, file_path)
        log_action(user_id, doc_id, "sign_document")
    except Exception as exc:
        return jsonify(error=str(exc)), 500
    return Response(signed_pdf, mimetype="application/pdf")


@app.get("/search")
def search_view():
    fields = ["title", "code", "tags", "department", "process"]
    filters = {f: request.args.get(f) for f in fields}
    results = []
    try:
        results = search_documents(filters)
    except Exception:
        session = get_session()
        query = session.query(Document)
        if filters["title"]:
            query = query.filter(Document.title.ilike(f"%{filters['title']}%"))
        if filters["code"]:
            query = query.filter(Document.code == filters["code"])
        if filters["tags"]:
            query = query.filter(Document.tags.contains(filters["tags"]))
        if filters["department"]:
            query = query.filter(Document.department == filters["department"])
        if filters["process"]:
            query = query.filter(Document.process == filters["process"])
        results = [
            {
                "id": d.id,
                "title": d.title,
                "code": d.code,
                "tags": d.tags,
                "department": d.department,
                "process": d.process,
            }
            for d in query.all()
        ]
        session.close()
    return render_template("search.html", results=results, filters=filters)


@app.get("/reports")
def reports_index():
    return render_template("reports.html")


@app.get("/reports/<kind>")
def report_download(kind):
    fmt = request.args.get("format", "json").lower()
    mapping = {
        "revisions": revision_report,
        "training": training_compliance_report,
        "pending-approvals": pending_approvals_report,
    }
    if fmt == "json":
        fn = mapping.get(kind)
        if not fn:
            return jsonify(error="unknown report"), 400
        return jsonify(fn())
    try:
        content, mime, ext = build_report(kind, fmt)
    except ValueError:
        return jsonify(error="unknown report or format"), 400
    return Response(
        content,
        mimetype=mime,
        headers={"Content-Disposition": f"attachment; filename={kind}.{ext}"},
    )


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
        log_action(user_id, None, f"assign_role:{role_name}")
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
    log_action(data.get("user_id"), doc_id, "save_revision")
    user_ids = [u.id for u in session.query(User).all()]
    notify_revision_time(doc, user_ids)
    session.close()
    return jsonify(ok=True, version=f"{doc.major_version}.{doc.minor_version}")


@app.post("/documents/<int:doc_id>/acknowledge")
def acknowledge_document(doc_id):
    data = request.get_json(silent=True) or {}
    user_id = data.get("user_id")
    if not user_id:
        return jsonify(error="user_id required"), 400
    session = get_session()
    try:
        doc = session.get(Document, doc_id)
        if not doc:
            return jsonify(error="document not found"), 404
        ack = (
            session.query(Acknowledgement)
            .filter_by(user_id=user_id, doc_id=doc_id)
            .first()
        )
        if not ack:
            ack = Acknowledgement(user_id=user_id, doc_id=doc_id)
            session.add(ack)
            session.commit()
            log_action(user_id, doc_id, "acknowledge_document")
        return jsonify(ok=True, acknowledged_at=ack.acknowledged_at.isoformat())
    finally:
        session.close()


@app.get("/notifications/<int:user_id>")
def notifications(user_id):
    session = get_session()
    try:
        published = session.query(Document).filter_by(status="Published").all()
        pending = []
        for doc in published:
            ack = (
                session.query(Acknowledgement)
                .filter_by(user_id=user_id, doc_id=doc.id)
                .first()
            )
            if not ack:
                pending.append({"doc_id": doc.id, "doc_key": doc.doc_key})
        return jsonify(pending_acknowledgements=pending)
    finally:
        session.close()


@app.get("/notifications/<int:user_id>/view")
def notifications_ui(user_id):
    return (
        "<html><body><h3>Pending Acknowledgements</h3>"\
        "<div id='list'></div>"\
        "<script>fetch('/notifications/" + str(user_id) + "').then(r=>r.json()).then(data=>{"\
        "document.getElementById('list').innerText = JSON.stringify(data.pending_acknowledgements);"\
        "});</script></body></html>"
    )


@app.route("/settings/notifications", methods=["GET", "POST"])
def notification_settings():
    user_id = request.args.get("user_id", type=int)
    if not user_id:
        return jsonify(error="user_id required"), 400
    session = get_session()
    settings = session.query(NotificationSetting).filter_by(user_id=user_id).first()
    if request.method == "POST":
        data = request.form or request.get_json(silent=True) or {}
        email_enabled = bool(data.get("email_enabled"))
        webhook_enabled = bool(data.get("webhook_enabled"))
        webhook_url = data.get("webhook_url")
        if not settings:
            settings = NotificationSetting(user_id=user_id)
            session.add(settings)
        settings.email_enabled = email_enabled
        settings.webhook_enabled = webhook_enabled
        settings.webhook_url = webhook_url
        session.commit()
        session.close()
        return redirect(url_for("notification_settings", user_id=user_id))
    settings_data = {
        "email_enabled": settings.email_enabled if settings else False,
        "webhook_enabled": settings.webhook_enabled if settings else False,
        "webhook_url": settings.webhook_url if settings else "",
    }
    session.close()
    return render_template(
        "settings_notifications.html", settings=settings_data, user_id=user_id
    )


@app.post("/training/evaluate")
def training_evaluate():
    data = request.get_json(silent=True) or {}
    user_id = data.get("user_id")
    answers = data.get("answers", {})
    if not user_id:
        return jsonify(error="user_id required"), 400
    # Demo correct answers
    correct = {"q1": "a", "q2": "b"}
    score = sum(1 for q, a in correct.items() if answers.get(q) == a)
    passed = score == len(correct)
    session = get_session()
    try:
        session.add(
            TrainingResult(
                user_id=user_id,
                score=score,
                max_score=len(correct),
                passed=passed,
            )
        )
        session.commit()
        log_action(user_id, None, "training_evaluate")
    finally:
        session.close()
    return jsonify(passed=passed, score=score, max_score=len(correct))


@app.post("/change_requests")
def create_change_request():
    data = request.get_json(silent=True) or {}
    session = get_session()
    cr = ChangeRequest(
        document_id=data.get("document_id"),
        description=data.get("description"),
    )
    session.add(cr)
    session.commit()
    log_action(data.get("user_id"), cr.document_id, "create_change_request")
    result = {"id": cr.id}
    session.close()
    return jsonify(result), 201


@app.put("/change_requests/<int:cr_id>")
def update_change_request(cr_id):
    data = request.get_json(silent=True) or {}
    session = get_session()
    cr = session.get(ChangeRequest, cr_id)
    if not cr:
        session.close()
        return jsonify(error="not found"), 404
    if data.get("document_id"):
        cr.document_id = data["document_id"]
    if "description" in data:
        cr.description = data["description"]
    session.commit()
    log_action(data.get("user_id"), cr_id, "update_change_request")
    session.close()
    return jsonify(ok=True)


@app.post("/deviations")
def create_deviation():
    data = request.get_json(silent=True) or {}
    session = get_session()
    dev = Deviation(
        document_id=data.get("document_id"),
        description=data.get("description"),
    )
    session.add(dev)
    session.commit()
    log_action(data.get("user_id"), dev.document_id, "create_deviation")
    result = {"id": dev.id}
    session.close()
    return jsonify(result), 201


@app.put("/deviations/<int:dev_id>")
def update_deviation(dev_id):
    data = request.get_json(silent=True) or {}
    session = get_session()
    dev = session.get(Deviation, dev_id)
    if not dev:
        session.close()
        return jsonify(error="not found"), 404
    if data.get("document_id"):
        dev.document_id = data["document_id"]
    if "description" in data:
        dev.description = data["description"]
    session.commit()
    log_action(data.get("user_id"), dev_id, "update_deviation")
    session.close()
    return jsonify(ok=True)


@app.post("/capa_actions")
def create_capa_action():
    data = request.get_json(silent=True) or {}
    session = get_session()
    act = CAPAAction(
        document_id=data.get("document_id"),
        action=data.get("action"),
        status=data.get("status", "Open"),
    )
    session.add(act)
    session.commit()
    log_action(data.get("user_id"), act.document_id, "create_capa_action")
    result = {"id": act.id}
    session.close()
    return jsonify(result), 201


@app.put("/capa_actions/<int:action_id>")
def update_capa_action(action_id):
    data = request.get_json(silent=True) or {}
    session = get_session()
    act = session.get(CAPAAction, action_id)
    if not act:
        session.close()
        return jsonify(error="not found"), 404
    if data.get("document_id"):
        act.document_id = data["document_id"]
    if "action" in data:
        act.action = data["action"]
    if "status" in data:
        act.status = data["status"]
    session.commit()
    log_action(data.get("user_id"), action_id, "update_capa_action")
    session.close()
    return jsonify(ok=True)


@app.get("/capa/track")
def capa_track():
    session = get_session()
    actions = session.query(CAPAAction).all()
    session.close()
    return render_template("capa_track.html", actions=actions)


@app.post("/forms/<form_name>/submit")
def submit_form(form_name):
    """Render a DOCXF form and return the resulting PDF while logging usage."""
    payload = request.get_json(silent=True) or {}
    user_id = payload.get("user_id")
    fields = payload.get("fields", {})
    if not user_id:
        return jsonify(error="user_id required"), 400
    pdf = render_form_to_pdf(form_name, fields)
    session = get_session()
    try:
        session.add(
            FormSubmission(form_name=form_name, user_id=user_id, data=fields)
        )
        session.commit()
        log_action(user_id, None, f"submit_form:{form_name}")
    finally:
        session.close()
    return Response(pdf, mimetype="application/pdf")


@app.get("/audit/export")
def audit_export():
    fmt = request.args.get("format", "csv").lower()
    session = get_session()
    logs = session.query(AuditLog).order_by(AuditLog.created_at.desc()).all()
    session.close()
    if fmt == "pdf":
        from fpdf import FPDF
        pdf = FPDF()
        pdf.add_page()
        pdf.set_font("Arial", size=12)
        pdf.cell(0, 10, "Audit Logs", ln=1)
        for log in logs:
            pdf.cell(0, 10, txt=f"{log.created_at.isoformat()} | user:{log.user_id} | doc:{log.doc_id} | {log.action}", ln=1)
        return Response(pdf.output(dest="S").encode("latin-1"), mimetype="application/pdf")
    else:
        output = io.StringIO()
        writer = csv.writer(output)
        writer.writerow(["timestamp", "user_id", "doc_id", "action"])
        for log in logs:
            writer.writerow([log.created_at.isoformat(), log.user_id, log.doc_id, log.action])
        return Response(
            output.getvalue(),
            mimetype="text/csv",
            headers={"Content-Disposition": "attachment; filename=audit_logs.csv"},
        )

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
