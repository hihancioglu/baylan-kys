import os, json, time, base64, hmac, hashlib, csv, io, secrets
from flask import (
    Flask,
    request,
    jsonify,
    redirect,
    url_for,
    render_template,
    Response,
    session,
    make_response,
)
from flask_wtf.csrf import CSRFProtect
from auth import auth_bp, init_app as auth_init, login_required, roles_required
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
    UserSetting,
    PersonalAccessToken,
    DepartmentVisibility,
    WorkflowStep,
    get_session,
    RoleEnum,
)
from search import index_document, search_documents
from sqlalchemy import func
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
from datetime import datetime
from queue import Queue

app = Flask(__name__, static_folder="static/dist")
app.secret_key = os.environ.get("SECRET_KEY", "dev")
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
)

app.config["SESSION_COOKIE_SECURE"] = (
    os.environ.get("SESSION_COOKIE_SECURE", "true").lower() == "true"
)


@app.after_request
def set_security_headers(response):
    response.headers["Content-Security-Policy"] = "default-src 'self'; frame-ancestors 'none'"
    response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
    response.headers["X-Frame-Options"] = "DENY"
    return response

CSRFProtect(app)
auth_init(app)
app.register_blueprint(auth_bp)

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


@app.context_processor
def inject_user():
    roles = session.get("roles", [])
    user = session.get("user")
    def has_role(role):
        return role in roles
    return {"current_user": user, "user_roles": roles, "has_role": has_role}

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


# --- Real-time count streaming ---
sse_clients = []


def _compute_counts(db, user_id, roles):
    approval_count = (
        db.query(WorkflowStep)
        .filter(
            WorkflowStep.status == "Pending",
            WorkflowStep.approver.in_(roles),
        )
        .count()
    )
    ack_count = (
        db.query(Document)
        .filter(Document.status == "Published")
        .outerjoin(
            Acknowledgement,
            (Acknowledgement.doc_id == Document.id)
            & (Acknowledgement.user_id == user_id),
        )
        .filter(Acknowledgement.id.is_(None))
        .count()
    )
    return {"approvals": approval_count, "acknowledgements": ack_count}


def broadcast_counts():
    db = get_session()
    try:
        for client in list(sse_clients):
            counts = _compute_counts(db, client["user_id"], client["roles"])
            client["queue"].put(json.dumps(counts))
    finally:
        db.close()


@app.get("/events")
@login_required
def sse_events():
    user = session.get("user")
    if not user:
        return "Unauthorized", 401
    user_id = user.get("id")
    roles = session.get("roles", [])
    q = Queue()
    client = {"user_id": user_id, "roles": roles, "queue": q}
    sse_clients.append(client)

    db = get_session()
    counts = _compute_counts(db, user_id, roles)
    db.close()

    def stream():
        yield f"data: {json.dumps(counts)}\n\n"
        try:
            while True:
                data = q.get()
                yield f"data: {data}\n\n"
        finally:
            sse_clients.remove(client)

    return Response(stream(), mimetype="text/event-stream")

@app.route("/")
@login_required
def dashboard():
    context = {
        "breadcrumbs": [{"title": "Dashboard"}],
        "pending_approvals": [],
        "mandatory_reading": [],
        "recent_revisions": [],
        "quick_access": [],
    }
    return render_template("dashboard.html", **context)


@app.get("/dashboard/cards/pending")
@login_required
def dashboard_cards_pending():
    return render_template(
        "partials/dashboard/_cards.html",
        card="pending",
        pending_approvals=[],
    )


@app.get("/dashboard/cards/mandatory")
@login_required
def dashboard_cards_mandatory():
    return render_template(
        "partials/dashboard/_cards.html",
        card="mandatory",
        mandatory_reading=[],
    )


@app.get("/dashboard/cards/recent")
@login_required
def dashboard_cards_recent():
    return render_template(
        "partials/dashboard/_cards.html",
        card="recent",
        recent_revisions=[],
    )


@app.get("/dashboard/cards/quick")
@login_required
def dashboard_cards_quick():
    return render_template(
        "partials/dashboard/_cards.html",
        card="quick",
        quick_access=[],
    )


@app.get("/health")
def health():
    return jsonify(status="ok")


@app.get("/archive")
@roles_required(RoleEnum.READER.value)
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


@app.get("/documents")
@roles_required(RoleEnum.READER.value)
def list_documents():
    session = get_session()
    query = session.query(Document)
    filters = {}
    code = request.args.get("code")
    if code:
        query = query.filter(Document.code == code)
        filters["code"] = code
    title = request.args.get("title")
    if title:
        query = query.filter(Document.title.ilike(f"%{title}%"))
        filters["title"] = title
    status = request.args.get("status")
    if status:
        query = query.filter(Document.status == status)
        filters["status"] = status
    department = request.args.get("department")
    if department:
        query = query.filter(Document.department == department)
        filters["department"] = department
    tag = request.args.get("tag")
    if tag:
        query = query.filter(Document.tags.contains(tag))
        filters["tag"] = tag

    page = int(request.args.get("page", 1))
    page_size = int(request.args.get("page_size", 20))
    total = query.count()
    pages = (total + page_size - 1) // page_size
    docs = (
        query.order_by(Document.id)
        .limit(page_size)
        .offset((page - 1) * page_size)
        .all()
    )
    session.close()

    params = request.args.to_dict()
    params.pop("page", None)
    params.pop("page_size", None)
    params["page_size"] = page_size

    context = {
        "documents": docs,
        "page": page,
        "pages": pages,
        "filters": filters,
        "params": params,
    }
    partial = bool(request.headers.get("HX-Request"))
    context["breadcrumbs"] = [
        {"title": "Home", "url": url_for("index")},
        {"title": "Documents"},
    ]
    return render_template("document_list.html", partial=partial, **context)


@app.get("/documents/<int:doc_id>")
@roles_required(RoleEnum.READER.value)
def document_detail(doc_id: int):
    session = get_session()
    doc = session.get(Document, doc_id)
    if not doc:
        session.close()
        return "Document not found", 404

    revision_id = request.args.get("revision_id", type=int)
    revisions = (
        session.query(DocumentRevision)
        .filter_by(doc_id=doc_id)
        .order_by(DocumentRevision.major_version.desc(), DocumentRevision.minor_version.desc())
        .all()
    )
    revision = None
    if revision_id:
        revision = (
            session.query(DocumentRevision)
            .filter_by(id=revision_id, doc_id=doc_id)
            .first()
        )
    session.close()
    partial = bool(request.headers.get("HX-Request"))
    return render_template(
        "document_detail.html",
        doc=doc,
        revisions=revisions,
        revision=revision,
        partial=partial,
        breadcrumbs=[
            {"title": "Home", "url": url_for("index")},
            {"title": "Documents", "url": url_for("list_documents")},
            {"title": doc.title},
        ],
    )


@app.get("/documents/<int:doc_id>/compare")
@roles_required(RoleEnum.READER.value)
def compare_document_versions(doc_id: int):
    rev_ids = request.args.getlist("rev_id", type=int)
    if len(rev_ids) < 2:
        return "Select at least two versions", 400
    session = get_session()
    doc = session.get(Document, doc_id)
    revisions = (
        session.query(DocumentRevision)
        .filter(DocumentRevision.doc_id == doc_id, DocumentRevision.id.in_(rev_ids))
        .order_by(DocumentRevision.major_version, DocumentRevision.minor_version)
        .all()
    )
    session.close()
    if len(revisions) < 2:
        return "Versions not found", 404
    if revisions[0].compare_result:
        diff_html = revisions[0].compare_result
    else:
        import difflib
        diff_html = difflib.HtmlDiff().make_table(
            (revisions[0].revision_notes or "").splitlines(),
            (revisions[1].revision_notes or "").splitlines(),
            fromdesc=f"{revisions[0].major_version}.{revisions[0].minor_version}",
            todesc=f"{revisions[1].major_version}.{revisions[1].minor_version}",
        )
    return render_template(
        "document_compare.html",
        doc_id=doc_id,
        revisions=revisions,
        diff=diff_html,
        breadcrumbs=[
            {"title": "Home", "url": url_for("index")},
            {"title": "Documents", "url": url_for("list_documents")},
            {"title": doc.title, "url": url_for("document_detail", doc_id=doc_id)},
            {"title": "Compare"},
        ],
    )


@app.post("/documents")
@roles_required(RoleEnum.CONTRIBUTOR.value)
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
@roles_required(RoleEnum.APPROVER.value, RoleEnum.PUBLISHER.value)
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


@app.get("/approvals")
@roles_required(RoleEnum.APPROVER.value)
def approval_queue():
    db = get_session()
    try:
        user_roles = session.get("roles", [])
        steps = (
            db.query(WorkflowStep)
            .join(Document)
            .filter(
                WorkflowStep.status == "Pending",
                WorkflowStep.approver.in_(user_roles),
            )
            .all()
        )
        return render_template(
            "approvals.html",
            steps=steps,
            breadcrumbs=[
                {"title": "Home", "url": url_for("index")},
                {"title": "Approvals"},
            ],
        )
    finally:
        db.close()


@app.post("/approvals/<int:step_id>/approve")
@roles_required(RoleEnum.APPROVER.value)
def approve_step(step_id: int):
    db = get_session()
    try:
        step = db.get(WorkflowStep, step_id)
        if not step:
            return "Not found", 404
        step.status = "Approved"
        step.approved_at = datetime.utcnow()
        db.commit()
        broadcast_counts()
        db.refresh(step)
        html = render_template("_approval_row.html", step=step)
        resp = make_response(html)
        resp.headers["HX-Trigger"] = json.dumps({"showToast": "Approved"})
        return resp
    finally:
        db.close()


@app.post("/approvals/<int:step_id>/reject")
@roles_required(RoleEnum.APPROVER.value)
def reject_step(step_id: int):
    db = get_session()
    try:
        step = db.get(WorkflowStep, step_id)
        if not step:
            return "Not found", 404
        step.status = "Rejected"
        db.commit()
        broadcast_counts()
        db.refresh(step)
        html = render_template("_approval_row.html", step=step)
        resp = make_response(html)
        resp.headers["HX-Trigger"] = json.dumps({"showToast": "Rejected"})
        return resp
    finally:
        db.close()


@app.get("/search")
@roles_required(RoleEnum.READER.value)
def search_view():
    keyword = request.args.get("q", "")
    filters = {f: request.args.get(f) for f in ["department", "status", "type"]}
    page = int(request.args.get("page", 1))
    results = []
    facets = {"department": {}, "status": {}, "type": {}}
    try:
        results, facets = search_documents(keyword, filters, page=page)
    except Exception:
        session = get_session()
        query = session.query(Document)
        if keyword:
            query = query.filter(Document.title.ilike(f"%{keyword}%"))
        if filters["department"]:
            query = query.filter(Document.department == filters["department"])
        if filters["status"]:
            query = query.filter(Document.status == filters["status"])
        if filters["type"]:
            if hasattr(Document, "type"):
                query = query.filter(Document.type == filters["type"])
            else:
                query = query.filter(Document.process == filters["type"])
        docs = query.offset((page - 1) * 10).limit(10).all()
        results = [
            {
                "id": d.id,
                "title": d.title,
                "code": d.code,
                "tags": d.tags,
                "department": d.department,
                "status": d.status,
                "type": getattr(d, "type", getattr(d, "process", "")),
            }
            for d in docs
        ]
        facets = {
            "department": {
                row[0]: row[1]
                for row in session.query(Document.department, func.count(Document.id)).group_by(Document.department)
            },
            "status": {
                row[0]: row[1]
                for row in session.query(Document.status, func.count(Document.id)).group_by(Document.status)
            },
        }
        if hasattr(Document, "type"):
            facet_query = session.query(Document.type, func.count(Document.id)).group_by(Document.type)
        else:
            facet_query = session.query(Document.process, func.count(Document.id)).group_by(Document.process)
        facets["type"] = {row[0]: row[1] for row in facet_query}
        session.close()
    return render_template(
        "search.html",
        results=results,
        keyword=keyword,
        filters=filters,
        facets=facets,
        page=page,
        breadcrumbs=[
            {"title": "Home", "url": url_for("index")},
            {"title": "Search"},
        ],
    )


@app.get("/reports")
@roles_required(RoleEnum.AUDITOR.value, RoleEnum.QUALITY_ADMIN.value)
def reports_index():
    return render_template(
        "reports.html",
        breadcrumbs=[
            {"title": "Home", "url": url_for("index")},
            {"title": "Reports"},
        ],
    )


@app.get("/reports/<kind>")
@roles_required(RoleEnum.AUDITOR.value, RoleEnum.QUALITY_ADMIN.value)
def report_download(kind):
    fmt = request.args.get("format", "json").lower()
    start = request.args.get("start")
    end = request.args.get("end")
    start_dt = datetime.fromisoformat(start) if start else None
    end_dt = datetime.fromisoformat(end) if end else None
    mapping = {
        "revisions": lambda: revision_report(start_dt, end_dt),
        "training": lambda: training_compliance_report(start_dt, end_dt),
        "pending-approvals": lambda: pending_approvals_report(start_dt, end_dt),
    }
    if fmt == "json":
        fn = mapping.get(kind)
        if not fn:
            return jsonify(error="unknown report"), 400
        return jsonify(fn())
    try:
        content, mime, ext = build_report(kind, fmt, start_dt, end_dt)
    except ValueError:
        return jsonify(error="unknown report or format"), 400
    return Response(
        content,
        mimetype=mime,
        headers={"Content-Disposition": f"attachment; filename={kind}.{ext}"},
    )


@app.post("/roles/assign")
@roles_required(RoleEnum.QUALITY_ADMIN.value)
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


@app.delete("/roles/assign")
@roles_required(RoleEnum.QUALITY_ADMIN.value)
def remove_role():
    """Remove a role from a user."""
    data = request.get_json(silent=True) or {}
    user_id = data.get("user_id")
    role_name = data.get("role")
    if not user_id or not role_name:
        return jsonify(error="user_id and role required"), 400
    session = get_session()
    try:
        role = session.query(Role).filter_by(name=role_name).first()
        if not role:
            return jsonify(error="role not found"), 404
        link = session.query(UserRole).filter_by(user_id=user_id, role_id=role.id).first()
        if link:
            session.delete(link)
            session.commit()
            log_action(user_id, None, f"remove_role:{role_name}")
        return jsonify(ok=True)
    finally:
        session.close()


@app.get("/admin/users")
@roles_required(RoleEnum.QUALITY_ADMIN.value)
def admin_users_page():
    """Render user list page."""
    db = get_session()
    try:
        users = db.query(User).all()
        return render_template(
            "admin/users.html",
            users=users,
            breadcrumbs=[
                {"title": "Home", "url": url_for("index")},
                {"title": "Admin"},
                {"title": "Users"},
            ],
        )
    finally:
        db.close()


@app.get("/admin/roles")
@roles_required(RoleEnum.QUALITY_ADMIN.value)
def admin_roles_page():
    """Render role assignment page."""
    db = get_session()
    try:
        users = db.query(User).all()
        roles = db.query(Role).all()
        return render_template(
            "admin/roles.html",
            users=users,
            roles=roles,
            breadcrumbs=[
                {"title": "Home", "url": url_for("index")},
                {"title": "Admin"},
                {"title": "Roles"},
            ],
        )
    finally:
        db.close()


@app.get("/admin/departments")
@roles_required(RoleEnum.QUALITY_ADMIN.value)
def admin_departments_page():
    """Render department visibility page."""
    db = get_session()
    try:
        departments = db.query(DepartmentVisibility).all()
        return render_template(
            "admin/departments.html",
            departments=departments,
            breadcrumbs=[
                {"title": "Home", "url": url_for("index")},
                {"title": "Admin"},
                {"title": "Departments"},
            ],
        )
    finally:
        db.close()


@app.get("/admin/api/users")
@roles_required(RoleEnum.QUALITY_ADMIN.value)
def list_users_api():
    """Return all users as JSON."""
    db = get_session()
    try:
        users = db.query(User).all()
        data = [
            {
                "id": u.id,
                "username": u.username,
                "email": u.email,
                "roles": [ur.role.name for ur in u.roles],
            }
            for u in users
        ]
        return jsonify(data)
    finally:
        db.close()


@app.post("/admin/api/users")
@roles_required(RoleEnum.QUALITY_ADMIN.value)
def create_user_api():
    data = request.get_json(silent=True) or {}
    username = data.get("username")
    email = data.get("email")
    if not username:
        return jsonify(error="username required"), 400
    db = get_session()
    try:
        user = User(username=username, email=email)
        db.add(user)
        db.commit()
        admin_id = session.get("user", {}).get("id")
        log_action(admin_id, None, f"create_user:{user.id}")
        return jsonify(id=user.id, username=user.username, email=user.email)
    finally:
        db.close()


@app.put("/admin/api/users/<int:user_id>")
@roles_required(RoleEnum.QUALITY_ADMIN.value)
def update_user_api(user_id):
    data = request.get_json(silent=True) or {}
    db = get_session()
    try:
        user = db.get(User, user_id)
        if not user:
            return jsonify(error="user not found"), 404
        user.username = data.get("username", user.username)
        user.email = data.get("email", user.email)
        db.commit()
        admin_id = session.get("user", {}).get("id")
        log_action(admin_id, None, f"update_user:{user_id}")
        return jsonify(ok=True)
    finally:
        db.close()


@app.delete("/admin/api/users/<int:user_id>")
@roles_required(RoleEnum.QUALITY_ADMIN.value)
def delete_user_api(user_id):
    db = get_session()
    try:
        user = db.get(User, user_id)
        if not user:
            return jsonify(error="user not found"), 404
        db.delete(user)
        db.commit()
        admin_id = session.get("user", {}).get("id")
        log_action(admin_id, None, f"delete_user:{user_id}")
        return jsonify(ok=True)
    finally:
        db.close()


@app.get("/admin/api/departments")
@roles_required(RoleEnum.QUALITY_ADMIN.value)
def list_departments_api():
    db = get_session()
    try:
        depts = db.query(DepartmentVisibility).all()
        data = [
            {"id": d.id, "name": d.name, "visible": d.visible}
            for d in depts
        ]
        return jsonify(data)
    finally:
        db.close()


@app.post("/admin/api/departments")
@roles_required(RoleEnum.QUALITY_ADMIN.value)
def create_department_api():
    data = request.get_json(silent=True) or {}
    name = data.get("name")
    if not name:
        return jsonify(error="name required"), 400
    db = get_session()
    try:
        dept = DepartmentVisibility(name=name, visible=data.get("visible", True))
        db.add(dept)
        db.commit()
        admin_id = session.get("user", {}).get("id")
        log_action(admin_id, None, f"create_department:{dept.id}")
        return jsonify(id=dept.id, name=dept.name, visible=dept.visible)
    finally:
        db.close()


@app.put("/admin/api/departments/<int:dept_id>")
@roles_required(RoleEnum.QUALITY_ADMIN.value)
def update_department_api(dept_id):
    data = request.get_json(silent=True) or {}
    db = get_session()
    try:
        dept = db.get(DepartmentVisibility, dept_id)
        if not dept:
            return jsonify(error="department not found"), 404
        if "name" in data:
            dept.name = data["name"]
        if "visible" in data:
            dept.visible = bool(data["visible"])
        db.commit()
        admin_id = session.get("user", {}).get("id")
        log_action(admin_id, None, f"update_department:{dept_id}")
        return jsonify(ok=True)
    finally:
        db.close()


@app.delete("/admin/api/departments/<int:dept_id>")
@roles_required(RoleEnum.QUALITY_ADMIN.value)
def delete_department_api(dept_id):
    db = get_session()
    try:
        dept = db.get(DepartmentVisibility, dept_id)
        if not dept:
            return jsonify(error="department not found"), 404
        db.delete(dept)
        db.commit()
        admin_id = session.get("user", {}).get("id")
        log_action(admin_id, None, f"delete_department:{dept_id}")
        return jsonify(ok=True)
    finally:
        db.close()

@app.route("/doc/<doc_key>/edit")
@roles_required(RoleEnum.CONTRIBUTOR.value)
def edit(doc_key):
    # doc_key: MinIO’daki dosya anahtarınız (örn: qdms/PRO-001_v1.docx)
    user = session.get("user") or {"id": "u1", "name": "Ibrahim H.", "email": "ih@baylan.local"}
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
                "comment": True,
            },
        },
        "documentType": "text",
        "editorConfig": {
            "callbackUrl": f"{os.environ['PORTAL_PUBLIC_BASE_URL']}/onlyoffice/callback/{doc_key}",
            "user": {"id": user["id"], "name": user["name"]},
            "mode": "edit",
        },
    }
    token = sign_payload(config)
    return render_template(
        "document_edit.html",
        editor_js=f"{ONLYOFFICE_PUBLIC_URL}/web-apps/apps/api/documents/api.js",
        config=config,
        token=token,
        token_header=ONLYOFFICE_JWT_HEADER,
        breadcrumbs=[
            {"title": "Home", "url": url_for("index")},
            {"title": "Edit Document"},
        ],
    )

@app.post("/documents/<int:doc_id>/revision")
@roles_required(RoleEnum.REVIEWER.value)
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
@roles_required(RoleEnum.READER.value)
def acknowledge_document(doc_id):
    user = session.get("user")
    if not user:
        return jsonify(error="user not logged in"), 401
    user_id = user["id"]
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
            broadcast_counts()
        return jsonify(ok=True, acknowledged_at=ack.acknowledged_at.isoformat())
    finally:
        session.close()


@app.get("/acknowledgements")
@roles_required(RoleEnum.READER.value)
def acknowledgements():
    user = session.get("user")
    if not user:
        return redirect(url_for("auth.login"))
    user_id = user.get("id")
    db = get_session()
    try:
        query = db.query(Document).filter_by(status="Published")
        filters = {}
        department = request.args.get("department")
        if department:
            query = query.filter(Document.department == department)
            filters["department"] = department
        tag = request.args.get("tag")
        if tag:
            query = query.filter(Document.tags.contains(tag))
            filters["tag"] = tag

        pending = []
        for doc in query.order_by(Document.id).all():
            ack = (
                db.query(Acknowledgement)
                .filter_by(user_id=user_id, doc_id=doc.id)
                .first()
            )
            if not ack:
                pending.append(doc)

        remaining = len(pending)
        context = {
            "documents": pending,
            "remaining": remaining,
            "filters": filters,
        }
        partial = bool(request.headers.get("HX-Request"))
        context["breadcrumbs"] = [
            {"title": "Home", "url": url_for("index")},
            {"title": "Acknowledgements"},
        ]
        return render_template("acknowledgements.html", partial=partial, **context)
    finally:
        db.close()


@app.get("/notifications/<int:user_id>")
@roles_required(RoleEnum.READER.value)
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
@roles_required(RoleEnum.READER.value)
def notifications_ui(user_id):
    return (
        "<html><body><h3>Pending Acknowledgements</h3>"\
        "<div id='list'></div>"\
        "<script>fetch('/notifications/" + str(user_id) + "').then(r=>r.json()).then(data=>{"\
        "document.getElementById('list').innerText = JSON.stringify(data.pending_acknowledgements);"\
        "});</script></body></html>"
    )


@app.route("/settings", methods=["GET", "POST"])
@roles_required(RoleEnum.READER.value)
def user_settings():
    user_id = request.args.get("user_id", type=int)
    if not user_id:
        return jsonify(error="user_id required"), 400
    session = get_session()
    settings = session.query(UserSetting).filter_by(user_id=user_id).first()
    if request.method == "POST":
        data = request.form or request.get_json(silent=True) or {}
        if not settings:
            settings = UserSetting(user_id=user_id)
            session.add(settings)
        settings.language = data.get("language", "en")
        settings.theme = data.get("theme", "light")
        settings.email_enabled = bool(data.get("email_enabled"))
        settings.webhook_enabled = bool(data.get("webhook_enabled"))
        settings.webhook_url = data.get("webhook_url")
        session.commit()
        session.close()
        return redirect(url_for("user_settings", user_id=user_id))
    settings_data = {
        "language": settings.language if settings else "en",
        "theme": settings.theme if settings else "light",
        "email_enabled": settings.email_enabled if settings else False,
        "webhook_enabled": settings.webhook_enabled if settings else False,
        "webhook_url": settings.webhook_url if settings else "",
    }
    tokens = session.query(PersonalAccessToken).filter_by(user_id=user_id).all()
    new_token = request.args.get("token")
    session.close()
    return render_template(
        "settings.html",
        settings=settings_data,
        tokens=tokens,
        user_id=user_id,
        new_token=new_token,
        breadcrumbs=[
            {"title": "Home", "url": url_for("index")},
            {"title": "Settings"},
        ],
    )


@app.route("/settings/tokens", methods=["POST"])
@roles_required(RoleEnum.READER.value)
def create_token():
    user_id = request.args.get("user_id", type=int)
    if not user_id:
        return jsonify(error="user_id required"), 400
    name = request.form.get("name")
    raw_token = secrets.token_hex(32)
    token_hash = hashlib.sha256(raw_token.encode()).hexdigest()
    session = get_session()
    session.add(PersonalAccessToken(user_id=user_id, name=name, token_hash=token_hash))
    session.commit()
    session.close()
    return redirect(url_for("user_settings", user_id=user_id, token=raw_token))


@app.route("/settings/tokens/<int:token_id>/delete", methods=["POST"])
@roles_required(RoleEnum.READER.value)
def delete_token(token_id):
    user_id = request.args.get("user_id", type=int)
    if not user_id:
        return jsonify(error="user_id required"), 400
    session = get_session()
    token = (
        session.query(PersonalAccessToken)
        .filter_by(id=token_id, user_id=user_id)
        .first()
    )
    if token:
        session.delete(token)
        session.commit()
    session.close()
    return redirect(url_for("user_settings", user_id=user_id))


@app.post("/training/evaluate")
@roles_required(RoleEnum.QUALITY_ADMIN.value)
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
@roles_required(RoleEnum.CONTRIBUTOR.value)
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
@roles_required(RoleEnum.QUALITY_ADMIN.value)
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
@roles_required(RoleEnum.CONTRIBUTOR.value)
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
@roles_required(RoleEnum.QUALITY_ADMIN.value)
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
@roles_required(RoleEnum.QUALITY_ADMIN.value)
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
@roles_required(RoleEnum.QUALITY_ADMIN.value)
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
@roles_required(RoleEnum.AUDITOR.value, RoleEnum.QUALITY_ADMIN.value)
def capa_track():
    session = get_session()
    actions = session.query(CAPAAction).all()
    session.close()
    return render_template(
        "capa_track.html",
        actions=actions,
        breadcrumbs=[
            {"title": "Home", "url": url_for("index")},
            {"title": "CAPA"},
        ],
    )


@app.post("/forms/<form_name>/submit")
@roles_required(RoleEnum.READER.value)
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
@roles_required(RoleEnum.AUDITOR.value, RoleEnum.QUALITY_ADMIN.value)
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
@login_required
def onlyoffice_callback(doc_key):
    data = request.get_json(silent=True) or {}
    status = data.get("status")
    file_url = data.get("url")
    db = get_session()
    try:
        doc = db.query(Document).filter_by(doc_key=doc_key).first()
        if doc and status in {2, 6} and file_url:
            doc.minor_version += 1
            rev = DocumentRevision(
                doc_id=doc.id,
                major_version=doc.major_version,
                minor_version=doc.minor_version,
                track_changes={"status": status, "url": file_url},
            )
            db.add(rev)
            db.commit()
            user_id = session.get("user", {}).get("id") if session.get("user") else None
            log_action(user_id, doc.id, f"onlyoffice_callback:{status}")
    finally:
        db.close()
    return jsonify(error=0)


if __name__ == "__main__":
    bind = os.environ.get("BIND", "0.0.0.0:5000")
    host, port = bind.split(":")
    debug = os.environ.get("DEBUG", "").lower() in {"1", "true", "yes"}
    app.run(host=host, port=int(port), debug=debug)
