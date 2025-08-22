import os, json, time, base64, hmac, hashlib, csv, io, secrets, logging, tempfile
from pathlib import Path
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
    DocumentStandard,
    DocumentRevision,
    DocumentPermission,
    User,
    Role,
    Acknowledgement,
    Notification,
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
    engine,
)
from search import index_document, search_documents
from sqlalchemy import func, or_, and_, inspect
from sqlalchemy.orm import sessionmaker
from ocr import extract_text
from docxf_render import render_form_and_store
from notifications import (
    notify_revision_time,
    notify_mandatory_read,
    notify_approval_queue,
    notify_user,
    subscribe,
    unsubscribe,
)
from reports import (
    build_report,
    revision_report,
    training_compliance_report,
    pending_approvals_report,
    standard_summary_report,
)
from signing import create_signed_pdf
from storage import generate_presigned_url, storage_client
from permissions import permission_check
from datetime import datetime
from queue import Queue

# Automatically run database migrations in non-SQLite environments.
def _run_migrations() -> None:
    db_url = os.environ.get("DATABASE_URL", "")
    if db_url.startswith("sqlite"):
        return
    from alembic import command
    from alembic.config import Config

    repo_root = Path(__file__).resolve().parent.parent
    cfg = Config(str(repo_root / "alembic.ini"))
    cfg.set_main_option("script_location", str(repo_root / "alembic"))
    command.upgrade(cfg, "head")


_run_migrations()

# Serve compiled assets from ``/static`` so the application's static URLs
# match the web server configuration.  Previously the Flask app exposed
# assets under ``/dist`` which did not align with Nginx's ``/static/``
# alias, causing requests like ``/dist/app.css`` to miss the static-file
# mapping and return 404s.  Using ``/static`` ensures ``asset_url``
# generates paths Nginx can serve correctly.
app = Flask(__name__, static_folder="static/dist", static_url_path="/static")
app.secret_key = os.environ.get("SECRET_KEY", "dev")
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
)

app.config["SESSION_COOKIE_SECURE"] = (
    os.environ.get("SESSION_COOKIE_SECURE", "true").lower() == "true"
)

# Temporary in-memory storage for document drafts keyed by a random ID
DOCUMENT_DRAFTS: dict[str, dict] = {}

# Allow tests to add routes even after the first request has been handled.
_orig_add_url_rule = app.add_url_rule

def _add_url_rule_late(*args, **kwargs):
    was_first = getattr(app, "_got_first_request", False)
    app._got_first_request = False
    try:
        return _orig_add_url_rule(*args, **kwargs)
    finally:
        app._got_first_request = was_first

app.add_url_rule = _add_url_rule_late


@app.after_request
def set_security_headers(response):
    response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
    response.headers["X-Frame-Options"] = "DENY"
    return response

CSRFProtect(app)
auth_init(app)
app.register_blueprint(auth_bp)


@app.errorhandler(403)
def handle_forbidden(error):
    app.logger.warning(
        "403 Forbidden: path=%s user=%s roles=%s reason=%s",
        request.path,
        session.get("user"),
        session.get("roles"),
        getattr(error, "description", ""),
    )
    return "Forbidden", 403

manifest_path = os.path.join(app.static_folder, "manifest.json")
_asset_manifest: dict[str, str] = {}

try:
    with open(manifest_path) as f:
        _asset_manifest = json.load(f)
except FileNotFoundError:
    logging.warning(
        "Asset manifest not found. Run portal/static/build.py to generate assets."
    )

if "base.js" not in _asset_manifest:
    logging.warning(
        "base.js missing from asset manifest. Run portal/static/build.py to generate assets."
    )
    _asset_manifest.setdefault("base.js", "base.js")


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


def log_action(user_id, doc_id, action, endpoint=None):
    """Persist an audit log entry."""
    Session = sessionmaker(bind=engine)
    session = Session()
    try:
        session.add(AuditLog(user_id=user_id, doc_id=doc_id, action=action, endpoint=endpoint))
        session.commit()
    finally:
        session.close()


# Demo quiz questions
QUIZ_QUESTIONS = [
    {
        "id": "q1",
        "text": "Sample question 1?",
        "options": [("a", "Option A"), ("b", "Option B"), ("c", "Option C")],
        "answer": "a",
    },
    {
        "id": "q2",
        "text": "Sample question 2?",
        "options": [("a", "Option A"), ("b", "Option B"), ("c", "Option C")],
        "answer": "b",
    },
]
QUIZ_ANSWERS = {q["id"]: q["answer"] for q in QUIZ_QUESTIONS}


def quiz_questions():
    return [{k: q[k] for k in ("id", "text", "options")} for q in QUIZ_QUESTIONS]


def _format_tags(value):
    """Validate and normalize tag input.

    Accepts either a list of strings or a comma-separated string and returns
    a comma-separated string of trimmed tags. Returns ``None`` if the input is
    not in an acceptable format or results in no tags.
    """

    if isinstance(value, list):
        if not all(isinstance(t, str) for t in value):
            return None
        tags = [t.strip() for t in value if isinstance(t, str) and t.strip()]
    elif isinstance(value, str):
        tags = [t.strip() for t in value.split(",") if t.strip()]
    else:
        return None

    return ",".join(tags) if tags else None


# Load ISO standards from environment.
def _parse_standard_map(raw: str) -> dict[str, str]:
    mapping: dict[str, str] = {}
    for item in raw.split(","):
        if ":" not in item:
            continue
        code, name = item.split(":", 1)
        code = code.strip()
        name = name.strip()
        if code:
            mapping[code] = name or code
    return mapping


# Parse ISO standards from environment. If none provided, standards are optional.
raw_standards = os.environ.get("ISO_STANDARDS", "")
STANDARD_MAP = _parse_standard_map(raw_standards) if raw_standards else {}
if STANDARD_MAP:
    STANDARD_MAP.setdefault("Uncategorized", "Uncategorized")
ALLOWED_STANDARDS = set(STANDARD_MAP.keys())


# -- Acknowledgement helpers -------------------------------------------------

def _assign_acknowledgements(db, doc_id, user_ids):
    """Create acknowledgement placeholders for given users."""
    for uid in set(user_ids):
        exists = (
            db.query(Acknowledgement)
            .filter_by(user_id=uid, doc_id=doc_id)
            .first()
        )
        if not exists:
            db.add(Acknowledgement(user_id=uid, doc_id=doc_id))


# --- Real-time count streaming ---
sse_clients = []


def _compute_counts(db, user_id, roles):
    inspector = inspect(db.get_bind())
    columns = {c["name"] for c in inspector.get_columns("workflow_steps")}

    approval_query = (
        db.query(func.count())
        .select_from(WorkflowStep)
        .filter(WorkflowStep.status == "Pending")
    )
    if "user_id" in columns:
        if user_id is not None:
            approval_query = approval_query.filter(WorkflowStep.user_id == user_id)
        else:
            approval_query = approval_query.filter(WorkflowStep.user_id.is_(None))
    approval_count = approval_query.scalar()
    ack_count = (
        db.query(Document)
        .filter(Document.status == "Published")
        .outerjoin(
            Acknowledgement,
            (Acknowledgement.doc_id == Document.id)
            & (Acknowledgement.user_id == user_id),
        )
        .filter(
            or_(
                Acknowledgement.id.is_(None),
                Acknowledgement.acknowledged_at.is_(None),
            )
        )
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
        yield f"event: counts\ndata: {json.dumps(counts)}\n\n"
        try:
            while True:
                data = q.get()
                yield f"event: counts\ndata: {data}\n\n"
        finally:
            sse_clients.remove(client)

    return Response(stream(), mimetype="text/event-stream")


@app.get("/notifications/stream")
@login_required
def notifications_stream():
    user = session.get("user")
    if not user:
        return "Unauthorized", 401
    user_id = user.get("id")
    q = subscribe(user_id)

    db = get_session()
    pending = db.query(Notification).filter_by(user_id=user_id, read=False).all()

    def stream():
        try:
            try:
                for n in pending:
                    yield f"data: {json.dumps({'id': n.id, 'message': n.message})}\n\n"
                    n.read = True
                db.commit()
            finally:
                db.close()
            while True:
                data = q.get()
                yield f"data: {data}\n\n"
        finally:
            unsubscribe(user_id, q)

    return Response(stream(), mimetype="text/event-stream")


def _get_pending_approvals(
    db, user_id: int | None, limit: int = 5, standard: str | None = None
):
    """Return titles and approval URLs for pending workflow steps.

    Older deployments may not yet have the ``user_id`` column.  If the column is
    missing, we avoid referencing it entirely to prevent ``UndefinedColumn``
    errors when querying.  Rather than loading whole ``WorkflowStep`` objects –
    which would implicitly include the missing column in the ``SELECT`` clause –
    we only select the specific columns we need.
    """

    query = (
        db.query(Document.title, WorkflowStep.id)
        .join(Document)
        .filter(WorkflowStep.status == "Pending")
    )

    if standard:
        query = (
            query.join(DocumentStandard, DocumentStandard.doc_id == Document.id)
            .filter(DocumentStandard.standard_code == standard)
        )

    inspector = inspect(db.get_bind())
    columns = {c["name"] for c in inspector.get_columns("workflow_steps")}
    if "user_id" in columns:
        if user_id is not None:
            query = query.filter(WorkflowStep.user_id == user_id)
        else:
            query = query.filter(WorkflowStep.user_id.is_(None))

    steps = (
        query.order_by(WorkflowStep.id.desc())
        .limit(limit)
        .all()
    )
    return [
        (title, url_for("approval_detail", id=step_id)) for title, step_id in steps
    ]


def _get_mandatory_reading(
    db, user_id: int | None, limit: int = 5, standard: str | None = None
):
    if not user_id:
        return []

    query = (
        db.query(Document)
        .filter(Document.status == "Published")
        .outerjoin(
            Acknowledgement,
            (Acknowledgement.doc_id == Document.id)
            & (Acknowledgement.user_id == user_id),
        )
        .filter(
            or_(
                Acknowledgement.id.is_(None),
                Acknowledgement.acknowledged_at.is_(None),
            )
        )
    )

    if standard:
        query = (
            query.join(
                DocumentStandard, DocumentStandard.doc_id == Document.id
            ).filter(DocumentStandard.standard_code == standard)
        )

    docs = (
        query.order_by(Document.id.desc())
        .limit(limit)
        .all()
    )
    return [
        (d.title, url_for("document_detail", doc_id=d.id)) for d in docs
    ]


def _get_recent_revisions(db, limit: int = 5):
    revisions = (
        db.query(DocumentRevision)
        .join(Document)
        .order_by(DocumentRevision.created_at.desc())
        .limit(limit)
        .all()
    )
    return [
        (
            r.document.title,
            url_for("document_detail", doc_id=r.doc_id, revision_id=r.id),
        )
        for r in revisions
    ]


def _get_search_shortcuts(limit: int = 5):
    shortcuts = [
        ("All Documents", url_for("list_documents")),
        ("My Approvals", url_for("approval_queue")),
        ("Yeni Doküman", url_for("new_document")),
    ]
    return shortcuts[:limit]

@app.route("/")
@login_required
def dashboard():
    db = get_session()
    try:
        user = session.get("user") or {}
        user_id = user.get("id")
        context = {
            "breadcrumbs": [{"title": "Dashboard"}],
            "pending_approvals": _get_pending_approvals(db, user_id),
            "mandatory_reading": _get_mandatory_reading(db, user_id),
            "recent_revisions": _get_recent_revisions(db),
            "search_shortcuts": _get_search_shortcuts(),
            "standards": sorted(ALLOWED_STANDARDS),
        }
        return render_template("dashboard.html", **context)
    finally:
        db.close()


@app.get("/profile")
@login_required
def profile_view():
    return render_template(
        "profile/index.html",
        breadcrumbs=[{"title": "Profile"}]
    )


@app.get("/api/dashboard/cards/<card>")
@login_required
def dashboard_cards(card):
    db = get_session()
    try:
        user = session.get("user") or {}
        user_id = user.get("id")
        standard = request.args.get("standard")
        context = {"card": card}
        if card == "pending":
            context["pending_approvals"] = _get_pending_approvals(
                db, user_id, standard=standard
            )
        elif card == "mandatory":
            context["mandatory_reading"] = _get_mandatory_reading(
                db, user_id, standard=standard
            )
        elif card == "recent":
            context["recent_revisions"] = _get_recent_revisions(db)
        elif card == "shortcuts":
            context["search_shortcuts"] = _get_search_shortcuts()
        else:
            return ("", 404)
        return render_template("partials/dashboard/_cards.html", **context)
    finally:
        db.close()


@app.get("/api/dashboard/pending-approvals")
@login_required
def api_dashboard_pending_approvals():
    limit = request.args.get("limit", type=int) or 5
    standard = request.args.get("standard")
    db = get_session()
    try:
        user = session.get("user") or {}
        user_id = user.get("id")
        items = _get_pending_approvals(db, user_id, limit, standard)
        return jsonify({"items": items, "error": None})
    except Exception as e:
        return jsonify({"items": [], "error": str(e)}), 500
    finally:
        db.close()


@app.get("/api/dashboard/mandatory-reading")
@login_required
def api_dashboard_mandatory_reading():
    limit = request.args.get("limit", type=int) or 5
    standard = request.args.get("standard")
    db = get_session()
    try:
        user = session.get("user") or {}
        items = _get_mandatory_reading(db, user.get("id"), limit, standard)
        return jsonify({"items": items, "error": None})
    except Exception as e:
        return jsonify({"items": [], "error": str(e)}), 500
    finally:
        db.close()


@app.get("/api/dashboard/recent-changes")
@login_required
def api_dashboard_recent_changes():
    limit = request.args.get("limit", type=int) or 5
    db = get_session()
    try:
        items = _get_recent_revisions(db, limit)
        return jsonify({"items": items, "error": None})
    except Exception as e:
        return jsonify({"items": [], "error": str(e)}), 500
    finally:
        db.close()


@app.get("/api/dashboard/search-shortcuts")
@login_required
def api_dashboard_search_shortcuts():
    limit = request.args.get("limit", type=int) or 5
    try:
        items = _get_search_shortcuts(limit)
        return jsonify({"items": items, "error": None})
    except Exception as e:
        return jsonify({"items": [], "error": str(e)}), 500


@app.get("/api/dashboard/standard-summary")
@login_required
def api_dashboard_standard_summary():
    db = get_session()
    try:
        rows = (
            db.query(
                DocumentStandard.standard_code,
                func.count().label("count"),
            )
            .join(Document)
            .group_by(DocumentStandard.standard_code)
            .all()
        )
        data = [
            {"standard": code, "count": count} for code, count in rows
        ]
        return jsonify(data)
    finally:
        db.close()


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


def _get_documents():
    db = get_session()
    filters: dict[str, object] = {}
    facets: dict[str, dict] = {}

    role_names = session.get("roles", [])
    scopes = {
        r.standard_scope
        for r in db.query(Role).filter(Role.name.in_(role_names)).all()
    }

    def _apply_scope(query):
        if "ALL" in scopes or not scopes:
            return query
        return (
            query.outerjoin(DocumentStandard, DocumentStandard.doc_id == Document.id)
            .filter(
                or_(
                    DocumentStandard.standard_code.in_(scopes),
                    Document.standard_code.in_(scopes),
                )
            )
            .distinct()
        )

    status = request.args.get("status")
    normalized_status = status.capitalize() if status else None
    department = request.args.get("department")
    standard = request.args.get("standard")
    tags = request.args.getlist("tags")
    q = request.args.get("q")

    page = int(request.args.get("page", 1))
    page_size = int(request.args.get("page_size", 20))

    use_search = bool(q or status or department or standard)

    if use_search:
        search_filters = {}
        if normalized_status:
            search_filters["status"] = normalized_status
            filters["status"] = normalized_status
        if department:
            search_filters["department"] = department
            filters["department"] = department
        if standard:
            search_filters["standard"] = standard
            filters["standard"] = standard
        if q:
            filters["q"] = q
        try:
            results, facets, total = search_documents(
                q, search_filters, page=page, per_page=page_size
            )
            ids = [int(r["id"]) for r in results]
            query = _apply_scope(db.query(Document).filter(Document.id.in_(ids)))
            docs = query.all()
            docs = sorted(docs, key=lambda d: ids.index(d.id))
            if tags:
                docs = [d for d in docs if d.tags and all(t in d.tags for t in tags)]
                filters["tags"] = tags
            pages = (total + page_size - 1) // page_size
        except RuntimeError:
            query = _apply_scope(db.query(Document))
            if normalized_status:
                query = query.filter(Document.status == normalized_status)
                filters["status"] = normalized_status
            if department:
                query = query.filter(Document.department == department)
                filters["department"] = department
            if standard:
                query = query.filter(Document.standard_code == standard)
                filters["standard"] = standard
            if tags:
                query = query.filter(and_(*[Document.tags.contains(t) for t in tags]))
                filters["tags"] = tags
            if q:
                like = f"%{q}%"
                query = query.filter(
                    or_(Document.title.ilike(like), Document.code.ilike(like))
                )
                filters["q"] = q
            total = query.count()
            pages = (total + page_size - 1) // page_size
            docs = (
                query.order_by(Document.id)
                .limit(page_size)
                .offset((page - 1) * page_size)
                .all()
            )
    else:
        query = _apply_scope(db.query(Document))
        if normalized_status:
            query = query.filter(Document.status == normalized_status)
            filters["status"] = normalized_status
        if department:
            query = query.filter(Document.department == department)
            filters["department"] = department
        if standard:
            query = query.filter(Document.standard_code == standard)
            filters["standard"] = standard
        if tags:
            query = query.filter(and_(*[Document.tags.contains(t) for t in tags]))
            filters["tags"] = tags
        if q:
            like = f"%{q}%"
            query = query.filter(
                or_(Document.title.ilike(like), Document.code.ilike(like))
            )
            filters["q"] = q
        total = query.count()
        pages = (total + page_size - 1) // page_size
        docs = (
            query.order_by(Document.id)
            .limit(page_size)
            .offset((page - 1) * page_size)
            .all()
        )

    # Sort documents by standard_code to ensure grouped display in templates
    docs = sorted(docs, key=lambda d: (d.standard_code or "", d.id))

    # Normalize missing standard codes to empty strings so template
    # grouping via ``groupby('standard_code')`` does not attempt to
    # compare ``None`` values, which causes a ``TypeError`` in Jinja's
    # sorting.
    for d in docs:
        if d.standard_code is None:
            d.standard_code = ""

    db.close()

    params = request.args.to_dict()
    params.pop("page", None)
    params.pop("page_size", None)
    params["page_size"] = page_size
    if normalized_status:
        params["status"] = normalized_status
    if standard:
        params["standard"] = standard

    return docs, page, pages, filters, params, facets


@app.get("/documents")
@roles_required(RoleEnum.READER.value)
def list_documents():
    docs, page, pages, filters, params, facets = _get_documents()
    template = "documents/list.html"
    if request.args.get("status", "").lower() == "archived":
        template = "documents/archived.html"

    session = get_session()
    departments = [d[0] for d in session.query(Document.department).distinct().all()]
    session.close()

    context = {
        "documents": docs,
        "page": page,
        "pages": pages,
        "filters": filters,
        "params": params,
        "facets": facets,
        "breadcrumbs": [
            {"title": "Home", "url": url_for("dashboard")},
            {"title": "Documents"},
        ],
        "departments": departments,
        "standards": sorted(ALLOWED_STANDARDS),
        "standard_map": STANDARD_MAP,
    }
    return render_template(template, **context)


@app.get("/documents/table")
@roles_required(RoleEnum.READER.value)
def documents_table():
    docs, page, pages, filters, params, facets = _get_documents()
    context = {
        "documents": docs,
        "page": page,
        "pages": pages,
        "filters": filters,
        "params": params,
        "facets": facets,
        "standards": sorted(ALLOWED_STANDARDS),
        "standard_map": STANDARD_MAP,
    }
    return render_template("documents/_table.html", **context)


@app.route("/documents/new", methods=["GET", "POST"])
@roles_required(RoleEnum.CONTRIBUTOR.value)
def new_document():
    step = request.args.get("step") or request.form.get("step") or "1"
    draft_id = session.get("new_doc_id")
    if not draft_id:
        draft_id = secrets.token_urlsafe(16)
        session["new_doc_id"] = draft_id
    data = DOCUMENT_DRAFTS.get(draft_id, {})

    if request.method == "POST":
        if step == "1":
            data["code"] = request.form.get("code", "").strip()
            data["title"] = request.form.get("title", "").strip()
            data["type"] = request.form.get("type", "").strip()
            data["department"] = request.form.get("department", "").strip()
            data["standard"] = request.form.get("standard", "").strip()
            tags = request.form.get("tags", "")
            data["tags"] = ",".join([t.strip() for t in tags.split(",") if t.strip()])
            DOCUMENT_DRAFTS[draft_id] = data
            return redirect(url_for("new_document", step=2))

        if step == "2":
            data.update(request.form.to_dict())
            uploaded = request.files.get("upload_file")
            if uploaded and uploaded.filename:
                _, ext = os.path.splitext(uploaded.filename)
                doc_key = f"{secrets.token_hex(16)}{ext}"
                try:
                    storage_client.put_object(
                        Key=doc_key,
                        Body=uploaded.read(),
                    )
                    data["uploaded_file_key"] = doc_key
                    data["uploaded_file_name"] = uploaded.filename
                except Exception as e:
                    data["upload_error"] = str(e)
            data["generate_docxf"] = bool(request.form.get("generate_docxf"))
            DOCUMENT_DRAFTS[draft_id] = data
            return redirect(url_for("new_document", step=3))

        data.update(request.form.to_dict())
        DOCUMENT_DRAFTS[draft_id] = data

        if step == "3":
            form_data = DOCUMENT_DRAFTS.pop(draft_id, {})
            session.pop("new_doc_id", None)
            user = session.get("user")
            roles = session.get("roles", [])
            with app.test_request_context("/api/documents", method="POST", json=form_data):
                session["user"] = user
                session["roles"] = roles
                response = create_document_api()
            if isinstance(response, tuple):
                resp, status = response
            else:
                resp, status = response, response.status_code
            if status == 201:
                doc_id = resp.get_json().get("id")
                return redirect(url_for("document_detail", doc_id=doc_id))
            return resp, status

    template = f"documents/new_step{step}.html"
    context = {
        "breadcrumbs": [
            {"title": "Home", "url": url_for("dashboard")},
            {"title": "Documents", "url": url_for("list_documents")},
            {"title": "New"},
        ],
        "errors": {},
        "form": data,
        "step": int(step),
    }
    if step == "1":
        context["standards"] = sorted(ALLOWED_STANDARDS)
        context["standard_map"] = STANDARD_MAP
    if step == "2":
        base_templates = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "templates"))
        template_options = {}
        for folder in ("forms", "procedures"):
            path = os.path.join(base_templates, folder)
            if os.path.isdir(path):
                template_options[folder] = [f for f in os.listdir(path) if os.path.isfile(os.path.join(path, f))]
        context["template_options"] = template_options
    return render_template(template, **context)


@app.get("/documents/<int:doc_id>")
@roles_required(RoleEnum.READER.value)
def document_detail(doc_id: int):
    session = get_session()
    doc = session.get(Document, doc_id)
    if not doc:
        session.close()
        return "Document not found", 404

    revision_id = request.args.get("revision_id", type=int)
    tab = request.args.get("tab")
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
    reviewers = (
        session.query(User)
        .join(User.roles)
        .filter(Role.name == RoleEnum.REVIEWER.value)
        .all()
    )
    session.close()
    partial = bool(request.headers.get("HX-Request"))
    template = (
        "partials/documents/_versions.html" if partial else "document_detail.html"
    )
    return render_template(
        template,
        doc=doc,
        revisions=revisions,
        revision=revision,
        reviewers=reviewers,
        active_tab="versions" if (revision_id or tab == "versions") else "summary",
        breadcrumbs=[
            {"title": "Home", "url": url_for("dashboard")},
            {"title": "Documents", "url": url_for("list_documents")},
            {"title": doc.title},
        ],
    )


@app.get("/documents/<int:doc_id>/workflow")
@roles_required(RoleEnum.READER.value)
def document_workflow(doc_id: int):
    db = get_session()
    doc = db.get(Document, doc_id)
    if not doc:
        db.close()
        return "Document not found", 404
    if doc.status not in {"Review", "Approved"}:
        db.close()
        return redirect(url_for("document_detail", doc_id=doc_id))
    steps = (
        db.query(WorkflowStep)
        .filter_by(doc_id=doc_id)
        .order_by(WorkflowStep.step_order)
        .all()
    )
    html = render_template(
        "document_workflow.html",
        doc=doc,
        steps=steps,
        breadcrumbs=[
            {"title": "Home", "url": url_for("dashboard")},
            {"title": "Documents", "url": url_for("list_documents")},
            {
                "title": doc.title,
                "url": url_for("document_detail", doc_id=doc_id),
            },
            {"title": "Workflow"},
        ],
    )
    db.close()
    return html


@app.get("/documents/<int:doc_id>/download")
@roles_required(RoleEnum.READER.value)
def download_document(doc_id: int):
    """Provide a presigned download URL for a document."""
    db = get_session()
    try:
        doc = db.get(Document, doc_id)
        if not doc:
            return "Document not found", 404
        user = session.get("user")
        if not user or not permission_check(user["id"], doc, download=True):
            return "Forbidden", 403
        url = generate_presigned_url(doc.doc_key)
        if not url:
            return "File not available", 404
        return redirect(url)
    finally:
        db.close()


@app.post("/workflow/start")
@roles_required(RoleEnum.CONTRIBUTOR.value)
def start_workflow():
    user = session.get("user")
    if not user:
        return jsonify(error="user not logged in"), 401
    doc_id = request.form.get("doc_id", type=int)
    reviewer_ids = [int(r) for r in request.form.getlist("reviewers") if r]
    db = get_session()
    try:
        doc = db.get(Document, doc_id)
        if not doc:
            return jsonify(error="document not found"), 404
        doc.status = "Review"
        steps = [
            WorkflowStep(
                doc_id=doc_id, step_order=i, user_id=rid, step_type="review"
            )
            for i, rid in enumerate(reviewer_ids, start=1)
        ]
        db.add_all(steps)
        db.commit()
        log_action(user["id"], doc_id, "start_workflow")
        notify_revision_time(doc, reviewer_ids)
        return jsonify(ok=True)
    finally:
        db.close()


@app.post("/api/workflow/start")
@roles_required(RoleEnum.CONTRIBUTOR.value)
def api_start_workflow():
    user = session.get("user")
    if not user:
        return jsonify(error="user not logged in"), 401
    data = request.get_json(silent=True) or {}
    try:
        doc_id = int(data.get("doc_id"))
    except (TypeError, ValueError):
        return jsonify(error="invalid doc_id"), 400
    reviewers = data.get("reviewers", [])
    approvers = data.get("approvers", [])
    if not isinstance(reviewers, list) or not isinstance(approvers, list):
        return jsonify(error="invalid payload"), 400
    reviewer_ids = [int(r) for r in reviewers]
    approver_ids = [int(a) for a in approvers]
    db = get_session()
    try:
        doc = db.get(Document, doc_id)
        if not doc:
            return jsonify(error="document not found"), 404
        doc.status = "Review"
        all_ids = reviewer_ids + approver_ids
        steps = []
        order = 1
        for uid in reviewer_ids:
            steps.append(
                WorkflowStep(
                    doc_id=doc_id,
                    step_order=order,
                    user_id=uid,
                    step_type="review",
                )
            )
            order += 1
        for uid in approver_ids:
            steps.append(
                WorkflowStep(
                    doc_id=doc_id,
                    step_order=order,
                    user_id=uid,
                    step_type="approval",
                )
            )
            order += 1
        db.add_all(steps)
        db.commit()
        log_action(user["id"], doc_id, "start_workflow")
        notify_revision_time(doc, list(set(all_ids)))
        return jsonify(ok=True)
    finally:
        db.close()


@app.get("/documents/<int:doc_id>/compare")
@roles_required(RoleEnum.READER.value)
def compare_document_versions(doc_id: int):
    rev_ids = request.args.getlist("rev_id", type=int)
    if len(rev_ids) < 2:
        return "Select at least two versions", 400
    session = get_session()
    doc = session.get(Document, doc_id)
    if not doc:
        session.close()
        return "Document not found", 404

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
            {"title": "Home", "url": url_for("dashboard")},
            {"title": "Documents", "url": url_for("list_documents")},
            {"title": doc.title, "url": url_for("document_detail", doc_id=doc_id)},
            {"title": "Compare"},
        ],
    )


@app.get("/api/documents/compare")
@roles_required(RoleEnum.READER.value)
def api_compare_documents():
    """Return OnlyOffice comparison configuration between two versions."""
    doc_id = request.args.get("doc_id", type=int)
    from_ver = request.args.get("from")
    to_ver = request.args.get("to")
    if not doc_id or not from_ver or not to_ver:
        return jsonify(error="doc_id, from and to required"), 400

    def _parse(v):
        try:
            maj, minr = map(int, v.split("."))
            return maj, minr
        except Exception:
            return None

    from_tuple = _parse(from_ver)
    to_tuple = _parse(to_ver)
    if not from_tuple or not to_tuple:
        return jsonify(error="invalid version"), 400

    db = get_session()
    doc = db.get(Document, doc_id)
    if not doc:
        db.close()
        return jsonify(error="document not found"), 404

    def _get_version(maj, minr):
        if doc.major_version == maj and doc.minor_version == minr:
            return {
                "url": storage_client.generate_presigned_url(doc.doc_key),
                "key": f"{doc.doc_key}:{maj}.{minr}",
                "title": doc.title or doc.doc_key.split('/')[-1],
            }
        rev = (
            db.query(DocumentRevision)
            .filter_by(doc_id=doc_id, major_version=maj, minor_version=minr)
            .first()
        )
        if rev and rev.track_changes and rev.track_changes.get("url"):
            return {
                "url": rev.track_changes.get("url"),
                "key": f"{doc.doc_key}:{maj}.{minr}",
                "title": doc.title or doc.doc_key.split('/')[-1],
            }
        return None

    from_doc = _get_version(*from_tuple)
    to_doc = _get_version(*to_tuple)
    db.close()
    if not from_doc or not to_doc:
        return jsonify(error="version not found"), 404

    user = session.get("user")
    user_name = ""
    if user:
        user_name = user.get("name") or user.get("username") or user.get("email", "")
    config = {
        "document": {
            "fileType": "docx",
            "key": from_doc["key"],
            "title": from_doc["title"],
            "url": from_doc["url"],
            "permissions": {"download": True},
        },
        "documentType": "text",
        "editorConfig": {
            "mode": "view",
            "user": {"id": user["id"], "name": user_name} if user else {},
            "compareFile": {
                "fileType": "docx",
                "key": to_doc["key"],
                "title": to_doc["title"],
                "url": to_doc["url"],
            },
        },
    }
    token = sign_payload(config)
    return jsonify(config=config, token=token, token_header=ONLYOFFICE_JWT_HEADER)


@app.post("/documents/<int:doc_id>/revert/<int:revision_id>")
@roles_required(RoleEnum.REVIEWER.value)
def revert_document(doc_id: int, revision_id: int):
    partial = bool(request.headers.get("HX-Request"))
    session = get_session()
    doc = session.get(Document, doc_id)
    rev = (
        session.query(DocumentRevision)
        .filter_by(id=revision_id, doc_id=doc_id)
        .first()
    )
    if not doc or not rev:
        session.close()
        return "Version not found", 404
    doc.minor_version += 1
    doc.revision_notes = rev.revision_notes
    new_rev = DocumentRevision(
        doc_id=doc.id,
        major_version=doc.major_version,
        minor_version=doc.minor_version,
        revision_notes=rev.revision_notes,
        track_changes=rev.track_changes,
        compare_result=rev.compare_result,
    )
    session.add(new_rev)
    session.commit()
    revisions = (
        session.query(DocumentRevision)
        .filter_by(doc_id=doc_id)
        .order_by(DocumentRevision.major_version.desc(), DocumentRevision.minor_version.desc())
        .all()
    )
    session.close()
    if partial:
        return render_template(
            "partials/documents/_versions.html",
            doc=doc,
            revisions=revisions,
            revision=None,
            active_tab="versions",
        )
    return redirect(url_for("document_detail", doc_id=doc_id))


@app.post("/documents/<int:doc_id>/rollback")
@roles_required(RoleEnum.REVIEWER.value)
def rollback_document(doc_id: int):
    """Rollback document to a specific version."""
    version_str = request.form.get("version") or ""
    try:
        major, minor = map(int, version_str.split("."))
    except ValueError:
        return "Invalid version", 400
    db = get_session()
    doc = db.get(Document, doc_id)
    if not doc:
        db.close()
        return "Document not found", 404
    rev = (
        db.query(DocumentRevision)
        .filter_by(doc_id=doc_id, major_version=major, minor_version=minor)
        .first()
    )
    if not rev:
        db.close()
        return "Revision not found", 404
    current_rev = DocumentRevision(
        doc_id=doc.id,
        major_version=doc.major_version,
        minor_version=doc.minor_version,
        revision_notes=doc.revision_notes,
    )
    db.add(current_rev)
    doc.major_version = rev.major_version
    doc.minor_version = rev.minor_version
    doc.revision_notes = rev.revision_notes
    db.delete(rev)
    db.commit()
    user = session.get("user") or {}
    log_action(user.get("id"), doc.id, "rollback_document")
    db.close()
    return redirect(url_for("document_detail", doc_id=doc_id, tab="versions"))


@app.post("/api/documents/<int:doc_id>/rollback")
@roles_required(RoleEnum.REVIEWER.value)
def rollback_document_api(doc_id: int):
    """Rollback document to a specific version via API."""
    version_str = request.args.get("version") or ""
    try:
        major, minor = map(int, version_str.split("."))
    except ValueError:
        return jsonify(error="Invalid version"), 400
    db = get_session()
    doc = db.get(Document, doc_id)
    if not doc:
        db.close()
        return jsonify(error="Document not found"), 404
    rev = (
        db.query(DocumentRevision)
        .filter_by(doc_id=doc_id, major_version=major, minor_version=minor)
        .first()
    )
    if not rev:
        db.close()
        return jsonify(error="Revision not found"), 404
    current_rev = DocumentRevision(
        doc_id=doc.id,
        major_version=doc.major_version,
        minor_version=doc.minor_version,
        revision_notes=doc.revision_notes,
    )
    db.add(current_rev)
    doc.major_version = rev.major_version
    doc.minor_version = rev.minor_version
    doc.revision_notes = rev.revision_notes
    db.commit()
    user = session.get("user") or {}
    resp = {
        "doc_id": doc.id,
        "major_version": doc.major_version,
        "minor_version": doc.minor_version,
    }
    log_action(user.get("id"), doc.id, "rollback_document")
    db.close()
    return jsonify(resp)


def _start_revision(doc: Document, version_type: str, notes: str, user: dict, db):
    old_rev = DocumentRevision(
        doc_id=doc.id,
        major_version=doc.major_version,
        minor_version=doc.minor_version,
        revision_notes=doc.revision_notes,
    )
    db.add(old_rev)
    if version_type == "major":
        doc.major_version += 1
        doc.minor_version = 0
    else:
        doc.minor_version += 1
    doc.status = "Draft"
    doc.revision_notes = notes
    db.commit()
    log_action(user.get("id"), doc.id, "start_revision")
    return doc


@app.post("/api/documents/<int:id>/revise")
@roles_required(RoleEnum.CONTRIBUTOR.value)
def revise_document_api(id: int):
    db = get_session()
    doc = db.get(Document, id)
    if not doc:
        db.close()
        return jsonify(error="Document not found"), 404
    data = request.get_json() or {}
    version_type = data.get("version_type", "minor")
    notes = data.get("revision_notes")
    user = session.get("user") or {}
    doc = _start_revision(doc, version_type, notes, user, db)
    resp = {
        "doc_id": doc.id,
        "major_version": doc.major_version,
        "minor_version": doc.minor_version,
        "status": doc.status,
    }
    db.close()
    return jsonify(resp)


@app.post("/documents/<int:id>/revise")
@roles_required(RoleEnum.CONTRIBUTOR.value)
def revise_document(id: int):
    db = get_session()
    doc = db.get(Document, id)
    if not doc:
        db.close()
        return "Document not found", 404
    version_type = request.form.get("version_type", "minor")
    notes = request.form.get("revision_notes")
    user = session.get("user") or {}
    _start_revision(doc, version_type, notes, user, db)
    db.close()
    return redirect(url_for("edit_document", doc_id=id))


@app.post("/documents")
@roles_required(RoleEnum.CONTRIBUTOR.value)
def create_document():
    code = request.form.get("code", "").strip()
    title = request.form.get("title", "").strip()
    department = request.form.get("department", "").strip()
    doc_type = request.form.get("type", "").strip()
    tags_input = request.form.getlist("tags")
    tags_raw = tags_input if len(tags_input) > 1 else (tags_input[0] if tags_input else None)
    tags_val = _format_tags(tags_raw)

    errors = {}
    if not code:
        errors["code"] = "Code is required."
    if not title:
        errors["title"] = "Title is required."
    if not department:
        errors["department"] = "Department is required."
    if not doc_type:
        errors["type"] = "Type is required."
    if not tags_val:
        errors["tags"] = "Invalid tags format."
    if errors:
        context = {
            "errors": errors,
            "form": request.form.to_dict(),
            "breadcrumbs": [
                {"title": "Home", "url": url_for("dashboard")},
                {"title": "Documents", "url": url_for("list_documents")},
                {"title": "New"},
            ],
        }
        return render_template("documents/new.html", **context), 400
    session_db = get_session()
    doc = Document(
        doc_key=secrets.token_hex(16),
        title=title,
        code=code,
        tags=tags_val,
        department=department,
        process=doc_type,
        status="Draft",
    )
    session_db.add(doc)
    user_id = (session.get("user") or {}).get("id") or (request.get_json(silent=True) or {}).get("user_id")
    if not user_id:
        session_db.rollback()
        session_db.close()
        return "user_id required", 400
    session_db.commit()
    log_action(user_id, doc.id, "create_document")
    session_db.close()
    return redirect(url_for("document_detail", doc_id=doc.id))


@app.post("/api/documents")
@roles_required(RoleEnum.CONTRIBUTOR.value)
def create_document_api():
    data = request.get_json(silent=True) or {}
    required_fields = [
        "code",
        "title",
        "type",
        "department",
        "tags",
        "uploaded_file_key",
    ]
    errors = {}
    for field in required_fields:
        value = data.get(field)
        if not value:
            errors[field] = f"{field} is required."
    standard = data.get("standard")
    if ALLOWED_STANDARDS:
        if not standard:
            errors["standard"] = "Standard is required."
        elif standard not in ALLOWED_STANDARDS:
            errors["standard"] = "Invalid standard."
    elif standard:
        errors["standard"] = "Invalid standard."
    if errors:
        return jsonify({"errors": errors}), 400

    tags_val = _format_tags(data.get("tags"))
    if not tags_val:
        return jsonify({"errors": {"tags": "Invalid tags format."}}), 400
    uploaded_file_key = data.get("uploaded_file_key")
    uploaded_file_name = data.get("uploaded_file_name", "")
    _, ext = os.path.splitext(uploaded_file_name)
    doc_key = uploaded_file_key
    if ext and not doc_key.endswith(ext):
        doc_key = f"{doc_key}{ext}"
    try:
        storage_client.head_object(Key=doc_key)
    except Exception as e:
        return jsonify({"errors": {"uploaded_file_key": str(e)}}), 400
    doc = Document(
        doc_key=doc_key,
        title=data.get("title"),
        code=data.get("code"),
        standard_code=standard,
        tags=tags_val,
        department=data.get("department"),
        process=data.get("type"),
        retention_period=data.get("retention_period"),
        status="Draft",
    )
    session_db = get_session()
    session_db.add(doc)
    user_id = (session.get("user") or {}).get("id") or data.get("user_id")
    if not user_id:
        session_db.rollback()
        session_db.close()
        return jsonify(error="user_id required"), 400
    session_db.commit()
    log_action(user_id, doc.id, "create_document")
    content = extract_text(doc_key)
    index_document(doc, content)
    user_ids = [u.id for u in session_db.query(User).all()]
    notify_mandatory_read(doc, user_ids)
    result = {"id": doc.id, "doc_key": doc_key, "standard": doc.standard_code}
    session_db.close()
    return jsonify(result), 201


@app.put("/api/documents/<int:id>")
@roles_required(RoleEnum.CONTRIBUTOR.value)
def update_document_api(id: int):
    data = request.get_json(silent=True) or {}
    session_db = get_session()
    doc = session_db.get(Document, id)
    if not doc:
        session_db.close()
        return jsonify(error="Document not found"), 404

    if "standard" in data:
        standard = data.get("standard")
        if ALLOWED_STANDARDS:
            if standard and standard not in ALLOWED_STANDARDS:
                session_db.close()
                return jsonify({"errors": {"standard": "Invalid standard."}}), 400
        elif standard:
            session_db.close()
            return jsonify({"errors": {"standard": "Invalid standard."}}), 400
        doc.standard_code = standard

    if "title" in data:
        doc.title = data.get("title")
    if "code" in data:
        doc.code = data.get("code")
    if "department" in data:
        doc.department = data.get("department")
    if "type" in data:
        doc.process = data.get("type")
    if "retention_period" in data:
        doc.retention_period = data.get("retention_period")
    if "tags" in data:
        tags_val = _format_tags(data.get("tags"))
        if not tags_val:
            session_db.close()
            return jsonify({"errors": {"tags": "Invalid tags format."}}), 400
        doc.tags = tags_val

    session_db.commit()
    user_id = (session.get("user") or {}).get("id") or data.get("user_id")
    if user_id:
        log_action(user_id, doc.id, "update_document")
    result = {"id": doc.id, "doc_key": doc.doc_key, "standard": doc.standard_code}
    session_db.close()
    return jsonify(result)


@app.post("/api/documents/from-docxf")
@roles_required(RoleEnum.CONTRIBUTOR.value)
def create_document_from_docxf():
    """Create a new document by rendering a DOCXF template."""
    data = request.get_json(silent=True) or {}
    form_id = data.get("form_id")
    payload = data.get("payload", {})
    if not form_id or not isinstance(payload, dict):
        return jsonify(error="form_id and payload required"), 400

    _, docx_key, pdf_key = render_form_and_store(form_id, payload)
    preview_key = pdf_key or docx_key
    preview_url = generate_presigned_url(preview_key) if preview_key else None

    session_db = get_session()
    try:
        doc = Document(
            doc_key=pdf_key,
            title=payload.get("title"),
            code=payload.get("code"),
            tags=_format_tags(payload.get("tags")),
            department=payload.get("department"),
            process=payload.get("process"),
            retention_period=payload.get("retention_period"),
            major_version=1,
            minor_version=0,
            status="Draft",
        )
        session_db.add(doc)
        session_db.flush()
        rev = DocumentRevision(doc_id=doc.id, major_version=1, minor_version=0)
        session_db.add(rev)
        session_db.commit()
        doc_id = doc.id
        version = f"{doc.major_version}.{doc.minor_version}"
    finally:
        session_db.close()

    return jsonify(
        {
            "id": doc_id,
            "docx_key": docx_key,
            "pdf_key": pdf_key,
            "preview_url": preview_url,
            "version": version,
        }
    ), 201


@app.post("/documents/<int:doc_id>/sign")
@roles_required(RoleEnum.APPROVER.value, RoleEnum.PUBLISHER.value)
def sign_document(doc_id: int):
    data = request.get_json(silent=True) or {}
    user_id = data.get("user_id")
    object_key = data.get("object_key")
    if not user_id or not object_key:
        return jsonify(error="user_id and object_key required"), 400

    temp_path = None
    try:
        obj = storage_client.get_object(Key=object_key)
        _, ext = os.path.splitext(object_key)
        with tempfile.NamedTemporaryFile(suffix=ext, delete=False) as tmp:
            tmp.write(obj["Body"].read())
            temp_path = tmp.name
        signed_pdf = create_signed_pdf(doc_id, user_id, temp_path)
        log_action(user_id, doc_id, "sign_document")
    except Exception as exc:
        return jsonify(error=str(exc)), 500
    finally:
        if temp_path and os.path.exists(temp_path):
            os.unlink(temp_path)
    return Response(signed_pdf, mimetype="application/pdf")


@app.get("/approvals")
@roles_required(RoleEnum.APPROVER.value, RoleEnum.REVIEWER.value)
def approval_queue():
    db = get_session()
    try:
        user = session.get("user") or {}
        user_id = user.get("id")
        steps = (
            db.query(WorkflowStep)
            .join(Document)
            .filter(
                WorkflowStep.status == "Pending",
                WorkflowStep.user_id == user_id,
            )
            .all()
        )
        template = (
            "partials/approvals/_table.html"
            if request.headers.get("HX-Request")
            else "approvals/list.html"
        )
        return render_template(
            template,
            steps=steps,
            breadcrumbs=[
                {"title": "Home", "url": url_for("dashboard")},
                {"title": "Approvals"},
            ],
        )
    finally:
        db.close()


@app.route("/approvals/<int:id>", methods=["GET"])
@roles_required(RoleEnum.APPROVER.value, RoleEnum.REVIEWER.value)
def approval_detail(id: int):
    db = get_session()
    try:
        step = db.get(WorkflowStep, id)
        if not step:
            return "Not found", 404
        doc = step.document
        user = session.get("user")
        user_name = ""
        if user:
            user_name = user.get("name") or user.get("username") or user.get("email", "")
        config = {
            "document": {
                "fileType": "docx",
                "key": f"{doc.doc_key}",
                "title": doc.title or doc.doc_key.split("/")[-1],
                "url": storage_client.generate_presigned_url(doc.doc_key),
                "permissions": {"download": True},
            },
            "documentType": "text",
            "editorConfig": {
                "user": {"id": user["id"], "name": user_name} if user else {},
                "mode": "view",
            },
        }
        token = sign_payload(config)
        if user:
            log_action(user["id"], doc.id, "view_approval")
        breadcrumbs = [
            {"title": "Home", "url": url_for("dashboard")},
            {"title": "Approvals", "url": url_for("approval_queue")},
            {"title": doc.title},
        ]
        return render_template(
            "approvals/detail.html",
            editor_js=f"{ONLYOFFICE_PUBLIC_URL}/web-apps/apps/api/documents/api.js",
            config=config,
            token=token,
            token_header=ONLYOFFICE_JWT_HEADER,
            step=step,
            breadcrumbs=breadcrumbs,
        )
    finally:
        db.close()


@app.post("/api/approvals/<int:step_id>/approve")
@roles_required(RoleEnum.APPROVER.value, RoleEnum.REVIEWER.value)
def api_approve_step(step_id: int):
    db = get_session()
    try:
        step = db.get(WorkflowStep, step_id)
        if not step:
            return "Not found", 404
        data = request.get_json(silent=True) or {}
        doc_id = step.doc_id
        step_order = step.step_order
        document = step.document
        step.status = "Approved"
        step.approved_at = datetime.utcnow()
        step.comment = data.get("comment")
        db.commit()
        user = session.get("user")
        if user:
            log_action(user["id"], doc_id, "approved")
        next_step = (
            db.query(WorkflowStep)
            .filter(
                WorkflowStep.doc_id == doc_id,
                WorkflowStep.step_order > step_order,
                WorkflowStep.status == "Pending",
            )
            .order_by(WorkflowStep.step_order)
            .first()
        )
        if next_step and next_step.user_id:
            notify_approval_queue(document, [next_step.user_id])
        broadcast_counts()
        step = db.get(WorkflowStep, step_id)
        html = render_template("partials/approvals/_row.html", step=step)
        resp = make_response(html)
        resp.headers["HX-Trigger"] = json.dumps({"showToast": "Approved"})
        return resp
    finally:
        db.close()


@app.post("/api/approvals/<int:step_id>/reject")
@roles_required(RoleEnum.APPROVER.value, RoleEnum.REVIEWER.value)
def api_reject_step(step_id: int):
    db = get_session()
    try:
        step = db.get(WorkflowStep, step_id)
        if not step:
            return "Not found", 404
        data = request.get_json(silent=True) or {}
        document = step.document
        step.status = "Rejected"
        step.approved_at = datetime.utcnow()
        step.comment = data.get("comment")
        db.commit()
        user = session.get("user")
        if user:
            log_action(user["id"], step.doc_id, "rejected")
        owner_id = getattr(document, "owner_id", None)
        if owner_id:
            notify_user(
                owner_id,
                f"Document {document.title} rejected",
                step.comment or f"Document {document.title} was rejected.",
            )
        broadcast_counts()
        step = db.get(WorkflowStep, step_id)
        html = render_template("partials/approvals/_row.html", step=step)
        resp = make_response(html)
        resp.headers["HX-Trigger"] = json.dumps({"showToast": "Rejected"})
        return resp
    finally:
        db.close()


@app.post("/approvals/<int:step_id>/approve")
@roles_required(RoleEnum.APPROVER.value, RoleEnum.REVIEWER.value)
def approve_step(step_id: int):
    db = get_session()
    try:
        step = db.get(WorkflowStep, step_id)
        if not step:
            return "Not found", 404
        step.status = "Approved"
        step.approved_at = datetime.utcnow()
        step.comment = request.form.get("comment")
        db.commit()
        user = session.get("user")
        if user:
            log_action(user["id"], step.doc_id, "approved")
        next_step = (
            db.query(WorkflowStep)
            .filter(
                WorkflowStep.doc_id == step.doc_id,
                WorkflowStep.step_order > step.step_order,
                WorkflowStep.status == "Pending",
            )
            .order_by(WorkflowStep.step_order)
            .first()
        )
        if next_step and next_step.user_id:
            notify_approval_queue(step.document, [next_step.user_id])
        broadcast_counts()
        db.refresh(step)
        html = render_template("partials/approvals/_row.html", step=step)
        resp = make_response(html)
        resp.headers["HX-Trigger"] = json.dumps({"showToast": "Approved"})
        return resp
    finally:
        db.close()


@app.post("/approvals/<int:step_id>/reject")
@roles_required(RoleEnum.APPROVER.value, RoleEnum.REVIEWER.value)
def reject_step(step_id: int):
    db = get_session()
    try:
        step = db.get(WorkflowStep, step_id)
        if not step:
            return "Not found", 404
        step.status = "Rejected"
        step.approved_at = datetime.utcnow()
        step.comment = request.form.get("comment")
        db.commit()
        user = session.get("user")
        if user:
            log_action(user["id"], step.doc_id, "rejected")
        owner_id = getattr(step.document, "owner_id", None)
        if owner_id:
            notify_user(
                owner_id,
                f"Document {step.document.title} rejected",
                step.comment or f"Document {step.document.title} was rejected.",
            )
        broadcast_counts()
        db.refresh(step)
        html = render_template("partials/approvals/_row.html", step=step)
        resp = make_response(html)
        resp.headers["HX-Trigger"] = json.dumps({"showToast": "Rejected"})
        return resp
    finally:
        db.close()


@app.get("/search")
@roles_required(RoleEnum.READER.value)
def search_view():
    keyword = request.args.get("q", "")
    page = int(request.args.get("page", 1))
    page_size = int(request.args.get("page_size", 20))
    session = get_session()
    query = session.query(Document)
    if keyword:
        query = query.filter(or_(Document.title.ilike(f"%{keyword}%"), Document.code.ilike(f"%{keyword}%")))
        total = query.count()
        docs = (
            query.order_by(Document.id)
            .limit(page_size)
            .offset((page - 1) * page_size)
            .all()
        )
    else:
        total = 0
        docs = []
    session.close()
    pages = (total + page_size - 1) // page_size if total else 1
    context = {
        "documents": docs,
        "keyword": keyword,
        "page": page,
        "pages": pages,
    }
    partial = bool(request.headers.get("HX-Request"))
    context["breadcrumbs"] = [
        {"title": "Home", "url": url_for("dashboard")},
        {"title": "Search"},
    ]
    template = "search/results.html" if partial else "search.html"
    return render_template(template, **context)
@app.get("/reports")
@roles_required(RoleEnum.AUDITOR.value, RoleEnum.QUALITY_ADMIN.value)
def reports_index():
    return render_template(
        "reports/index.html",
        breadcrumbs=[
            {"title": "Home", "url": url_for("dashboard")},
            {"title": "Reports"},
        ],
    )


@app.get("/reports/export")
@roles_required(RoleEnum.AUDITOR.value, RoleEnum.QUALITY_ADMIN.value)
def reports_export():
    kind = request.args.get("kind", "revisions")
    fmt = request.args.get("type", "csv").lower()
    start = request.args.get("start")
    end = request.args.get("end")
    start_dt = datetime.fromisoformat(start) if start else None
    end_dt = datetime.fromisoformat(end) if end else None
    try:
        content, mime, ext = build_report(kind, fmt, start_dt, end_dt)
    except ValueError:
        return jsonify(error="unknown report or format"), 400
    return Response(
        content,
        mimetype=mime,
        headers={"Content-Disposition": f"attachment; filename={kind}.{ext}"},
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
        "standard-summary": lambda: standard_summary_report(start_dt, end_dt),
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
    admin_id = session.get("user", {}).get("id")
    db = get_session()
    try:
        user = db.get(User, user_id)
        if not user:
            user = User(id=user_id, username=data.get("username", str(user_id)), email=data.get("email"))
            db.add(user)
            db.commit()
        role = db.query(Role).filter_by(name=role_name).first()
        if not role:
            role = Role(name=role_name)
            db.add(role)
            db.commit()
        log_action(admin_id, None, f"assign_role_before:{user_id}:{role_name}", endpoint="/roles/assign")
        if role not in user.roles:
            user.roles.append(role)
        db.commit()
        log_action(admin_id, None, f"assign_role_after:{user_id}:{role_name}", endpoint="/roles/assign")
        return jsonify(ok=True)
    finally:
        db.close()


@app.delete("/roles/assign")
@roles_required(RoleEnum.QUALITY_ADMIN.value)
def remove_role():
    """Remove a role from a user."""
    data = request.get_json(silent=True) or {}
    user_id = data.get("user_id")
    role_name = data.get("role")
    if not user_id or not role_name:
        return jsonify(error="user_id and role required"), 400
    admin_id = session.get("user", {}).get("id")
    db = get_session()
    try:
        user = db.get(User, user_id)
        role = db.query(Role).filter_by(name=role_name).first()
        if not user or not role:
            return jsonify(error="role not found"), 404
        log_action(admin_id, None, f"remove_role_before:{user_id}:{role_name}", endpoint="/roles/assign")
        if role in user.roles:
            user.roles.remove(role)
            db.commit()
        log_action(admin_id, None, f"remove_role_after:{user_id}:{role_name}", endpoint="/roles/assign")
        return jsonify(ok=True)
    finally:
        db.close()


@app.post("/roles")
@roles_required(RoleEnum.QUALITY_ADMIN.value)
def create_role():
    """Create a new role."""
    data = request.get_json(silent=True) or {}
    role_name = data.get("role")
    standard_scope = (data.get("standard_scope") or "ALL").upper()
    if not role_name:
        return jsonify(error="role required"), 400
    if standard_scope != "ALL" and standard_scope not in ALLOWED_STANDARDS:
        return jsonify(error="invalid standard_scope"), 400
    session = get_session()
    try:
        existing = session.query(Role).filter_by(name=role_name).first()
        if existing:
            return jsonify(error="role exists"), 400
        role = Role(name=role_name, standard_scope=standard_scope)
        session.add(role)
        session.commit()
        log_action(None, None, f"create_role:{role_name}")
        return jsonify(ok=True)
    finally:
        session.close()


@app.delete("/roles")
@roles_required(RoleEnum.QUALITY_ADMIN.value)
def delete_role():
    """Delete a role entirely."""
    data = request.get_json(silent=True) or {}
    role_name = data.get("role")
    if not role_name:
        return jsonify(error="role required"), 400
    session = get_session()
    try:
        role = session.query(Role).filter_by(name=role_name).first()
        if not role:
            return jsonify(error="role not found"), 404
        role.users.clear()
        session.delete(role)
        session.commit()
        log_action(None, None, f"delete_role:{role_name}")
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
        roles = db.query(Role).all()
        return render_template(
            "admin/users.html",
            users=users,
            roles=roles,
            breadcrumbs=[
                {"title": "Home", "url": url_for("dashboard")},
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
            standards=sorted(ALLOWED_STANDARDS),
            breadcrumbs=[
                {"title": "Home", "url": url_for("dashboard")},
                {"title": "Admin"},
                {"title": "Roles"},
            ],
        )
    finally:
        db.close()


@app.get("/admin/document-standards")
@roles_required(RoleEnum.QUALITY_ADMIN.value)
def admin_document_standards_page():
    """Render document standard mapping page."""
    db = get_session()
    try:
        docs = db.query(Document).order_by(Document.id).all()
        return render_template(
            "admin/document_standards.html",
            documents=docs,
            standards=sorted(ALLOWED_STANDARDS),
            standard_map=STANDARD_MAP,
            breadcrumbs=[
                {"title": "Home", "url": url_for("dashboard")},
                {"title": "Admin"},
                {"title": "Document Standards"},
            ],
        )
    finally:
        db.close()


@app.route("/admin/document-standards/<int:doc_id>", methods=["POST", "PUT"])
@roles_required(RoleEnum.QUALITY_ADMIN.value)
def update_document_standard(doc_id: int):
    data = request.get_json(silent=True) or {}
    standard = data.get("standard") or request.form.get("standard")
    if not standard or standard not in ALLOWED_STANDARDS:
        if request.is_json:
            return jsonify(error="Invalid standard"), 400
        return "Invalid standard", 400
    db = get_session()
    doc = db.get(Document, doc_id)
    if not doc:
        db.close()
        if request.is_json:
            return jsonify(error="Document not found"), 404
        return "Document not found", 404
    doc.standard_code = standard
    doc.standards = [DocumentStandard(standard_code=standard)]
    db.commit()
    user_id = (session.get("user") or {}).get("id")
    if user_id:
        log_action(user_id, doc_id, "update_document_standard")
    db.close()
    if request.is_json:
        return jsonify(ok=True)
    return redirect(url_for("admin_document_standards_page"))


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
                {"title": "Home", "url": url_for("dashboard")},
                {"title": "Admin"},
                {"title": "Departments"},
            ],
        )
    finally:
        db.close()


@app.get("/admin/audit")
@roles_required(RoleEnum.QUALITY_ADMIN.value)
def admin_audit_page():
    """Render audit log list page."""
    db = get_session()
    try:
        logs = db.query(AuditLog).order_by(AuditLog.created_at.desc()).limit(100).all()
        return render_template(
            "admin/audit.html",
            logs=logs,
            breadcrumbs=[
                {"title": "Home", "url": url_for("dashboard")},
                {"title": "Admin"},
                {"title": "Audit Logs"},
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
                "roles": [role.name for role in u.roles],
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

@app.get("/documents/<int:doc_id>/edit")
@roles_required(RoleEnum.CONTRIBUTOR.value)
def edit_document(doc_id):
    db = get_session()
    doc = db.get(Document, doc_id)
    if not doc:
        db.close()
        return "Document not found", 404
    user = session.get("user") or {"id": "u1", "name": "Ibrahim H.", "email": "ih@baylan.local"}
    user_name = user.get("name") or user.get("username") or user.get("email", "")
    public_base_url = os.environ.get(
        "PORTAL_PUBLIC_BASE_URL", request.host_url.rstrip("/")
    )
    # Defaults to the incoming request's host when PORTAL_PUBLIC_BASE_URL is unset
    config = {
        "document": {
            "fileType": "docx",
            "key": f"{doc.doc_key}",
            "title": doc.title or doc.doc_key.split('/')[-1],
            "url": storage_client.generate_presigned_url(doc.doc_key),
            "permissions": {
                "edit": True,
                "download": True,
                "review": True,
                "comment": True,
            },
        },
        "documentType": "text",
        "editorConfig": {
            "callbackUrl": f"{public_base_url}/onlyoffice/callback/{doc.doc_key}",
            "user": {"id": user["id"], "name": user_name},
            "mode": "edit",
        },
    }
    token = sign_payload(config)
    db.close()
    return render_template(
        "documents/edit.html",
        editor_js=f"{ONLYOFFICE_PUBLIC_URL}/web-apps/apps/api/documents/api.js",
        config=config,
        token=token,
        token_header=ONLYOFFICE_JWT_HEADER,
        doc_id=doc_id,
        breadcrumbs=[
            {"title": "Home", "url": url_for("dashboard")},
            {"title": "Documents", "url": url_for("list_documents")},
            {"title": doc.title, "url": url_for("document_detail", doc_id=doc_id)},
            {"title": "Edit"},
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


@app.post("/api/documents/<int:id>/publish")
@app.post("/documents/<int:id>/publish")  # Backward compatibility
@roles_required(RoleEnum.PUBLISHER.value)
def publish_document(id: int):
    db = get_session()
    try:
        doc = db.get(Document, id)
        if not doc:
            return "Not found", 404
        if doc.status != "Approved":
            return "Document not approved", 400
        doc.status = "Published"
        user_ids = set()
        for uid in request.form.getlist("users"):
            try:
                user_ids.add(int(uid))
            except (TypeError, ValueError):
                continue
        role_names = request.form.getlist("roles")
        if role_names:
            roles = db.query(Role).filter(Role.name.in_(role_names)).all()
            for role in roles:
                for user in role.users:
                    user_ids.add(user.id)
        _assign_acknowledgements(db, doc.id, user_ids)
        db.commit()
        if user_ids:
            notify_mandatory_read(doc, list(user_ids))
        publisher = session.get("user")
        if publisher:
            log_action(publisher["id"], doc.id, "publish_document")
        broadcast_counts()
        if request.headers.get("HX-Request"):
            resp = make_response("", 204)
            resp.headers["HX-Redirect"] = url_for("document_detail", doc_id=doc.id)
            resp.headers["HX-Trigger"] = json.dumps({"showToast": "Saved"})
            return resp
        return redirect(url_for("list_documents", status="Published"))
    finally:
        db.close()


@app.post("/documents/<int:doc_id>/republish")
@roles_required(RoleEnum.PUBLISHER.value)
def republish_document(doc_id: int):
    db = get_session()
    try:
        doc = db.get(Document, doc_id)
        if not doc:
            return "Not found", 404
        doc.status = "Published"
        doc.archived_at = None
        db.commit()
        publisher = session.get("user")
        if publisher:
            log_action(publisher["id"], doc.id, "republish_document")
        broadcast_counts()
        if request.headers.get("HX-Request"):
            resp = make_response("", 204)
            resp.headers["HX-Redirect"] = url_for("document_detail", doc_id=doc.id)
            resp.headers["HX-Trigger"] = json.dumps({"showToast": "Saved"})
            return resp
        return redirect(url_for("list_documents", status="archived"))
    finally:
        db.close()

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
            ack = Acknowledgement(
                user_id=user_id, doc_id=doc_id, acknowledged_at=datetime.utcnow()
            )
            session.add(ack)
            session.commit()
            log_action(user_id, doc_id, "acknowledge_document")
            broadcast_counts()
        elif ack.acknowledged_at is None:
            ack.acknowledged_at = datetime.utcnow()
            session.commit()
            log_action(user_id, doc_id, "acknowledge_document")
            broadcast_counts()
        return jsonify(
            ok=True, acknowledged_at=ack.acknowledged_at.isoformat()
        )
    finally:
        session.close()


@app.post("/api/ack/assign")
@app.post("/ack/assign")  # Backward compatibility
@roles_required(RoleEnum.PUBLISHER.value)
def assign_acknowledgements_endpoint():
    """Assign acknowledgements for the given document.

    Expects JSON payload ``{"doc_id": int, "targets": [user_id|role_name, ...]}``
    where each target is either a user ID (int) or a role name (str). Any
    provided role name will be expanded to all users that have that role before
    creating acknowledgement placeholders.
    """

    data = request.get_json(silent=True) or {}
    doc_id = data.get("doc_id")
    targets = data.get("targets", [])
    if not doc_id:
        return jsonify(error="doc_id required"), 400
    db = get_session()
    try:
        doc = db.get(Document, doc_id)
        if not doc:
            return jsonify(error="document not found"), 404
        if doc.status != "Published":
            return jsonify(error="document not published"), 400
        user_ids = set()
        for tgt in targets:
            if isinstance(tgt, int) or (isinstance(tgt, str) and tgt.isdigit()):
                user_ids.add(int(tgt))
            elif isinstance(tgt, str):
                role = db.query(Role).filter_by(name=tgt).first()
                if role:
                    for user in role.users:
                        user_ids.add(user.id)
        _assign_acknowledgements(db, doc_id, user_ids)
        db.commit()
        if doc and user_ids:
            notify_mandatory_read(doc, list(user_ids))
        broadcast_counts()
        return jsonify(ok=True)
    finally:
        db.close()


@app.get("/mandatory-reading")
@login_required
def mandatory_reading():
    """Display mandatory reading assignments."""
    filter_val = request.args.get("filter", "all")
    db = get_session()
    try:
        query = db.query(Acknowledgement).join(User)
        if filter_val == "unread":
            query = query.filter(Acknowledgement.acknowledged_at.is_(None))
        acks = query.order_by(User.username).all()
        assignments = [
            {
                "id": ack.id,
                "assignee": ack.user.username,
                "read_date": ack.acknowledged_at.strftime("%Y-%m-%d") if ack.acknowledged_at else None,
                "confirmed": ack.acknowledged_at is not None,
            }
            for ack in acks
        ]
    finally:
        db.close()
    breadcrumbs = [
        {"title": "Home", "url": url_for("dashboard")},
        {"title": "Mandatory Reading"},
    ]
    return render_template(
        "mandatory_reading.html",
        assignments=assignments,
        filter=filter_val,
        breadcrumbs=breadcrumbs,
    )


@app.post("/mandatory-reading/<int:assignment_id>/confirm")
@login_required
def confirm_assignment(assignment_id: int):
    """Confirm a single assignment."""
    db = get_session()
    try:
        ack = db.get(Acknowledgement, assignment_id)
        if not ack:
            return jsonify(error="assignment not found"), 404
        if ack.acknowledged_at is None:
            ack.acknowledged_at = datetime.utcnow()
            db.commit()
        assignment = {
            "id": ack.id,
            "assignee": ack.user.username,
            "read_date": ack.acknowledged_at.strftime("%Y-%m-%d") if ack.acknowledged_at else None,
            "confirmed": True,
        }
        return render_template("partials/_mandatory_row.html", assignment=assignment)
    finally:
        db.close()


@app.post("/mandatory-reading/confirm-bulk")
@login_required
def confirm_assignments_bulk():
    """Confirm multiple assignments."""
    ids = request.form.getlist("assignment_ids")
    db = get_session()
    try:
        if ids:
            acks = db.query(Acknowledgement).filter(Acknowledgement.id.in_(ids)).all()
            for ack in acks:
                if ack.acknowledged_at is None:
                    ack.acknowledged_at = datetime.utcnow()
            db.commit()
        filter_val = request.args.get("filter", "all")
        query = db.query(Acknowledgement).join(User)
        if filter_val == "unread":
            query = query.filter(Acknowledgement.acknowledged_at.is_(None))
        acks = query.order_by(User.username).all()
        assignments = [
            {
                "id": ack.id,
                "assignee": ack.user.username,
                "read_date": ack.acknowledged_at.strftime("%Y-%m-%d") if ack.acknowledged_at else None,
                "confirmed": ack.acknowledged_at is not None,
            }
            for ack in acks
        ]
        return render_template("partials/_mandatory_body.html", assignments=assignments)
    finally:
        db.close()


@app.route("/ack", methods=["GET"], endpoint="ack.list")
@roles_required(RoleEnum.READER.value)
def ack_list():
    """Display pending acknowledgements for the current user."""
    user = session.get("user")
    if not user:
        return redirect(url_for("auth.login"))
    user_id = user.get("id")
    db = get_session()
    try:
        query = (
            db.query(Document)
            .filter(Document.status == "Published")
            .outerjoin(
                Acknowledgement,
                (Acknowledgement.doc_id == Document.id)
                & (Acknowledgement.user_id == user_id),
            )
            .filter(
                or_(
                    Acknowledgement.id.is_(None),
                    Acknowledgement.acknowledged_at.is_(None),
                )
            )
        )

        filters = {}
        status = request.args.get("status")
        if status:
            query = query.filter(Document.status == status)
            filters["status"] = status
        due = request.args.get("due")
        if due:
            try:
                due_dt = datetime.fromisoformat(due)
                query = query.filter(Document.created_at <= due_dt)
                filters["due"] = due
            except ValueError:
                pass

        docs = query.order_by(Document.id).all()
        acknowledgements = [
            {
                "id": d.id,
                "code": d.code,
                "title": d.title,
                "status": d.status,
                "due_date": (d.created_at.date().isoformat() if d.created_at else None),
            }
            for d in docs
        ]
        context = {
            "acknowledgements": acknowledgements,
            "remaining": len(acknowledgements),
            "filters": filters,
        }
        context["breadcrumbs"] = [
            {"title": "Home", "url": url_for("dashboard")},
            {"title": "Acknowledgements"},
        ]
        partial = bool(request.headers.get("HX-Request"))
        return render_template("ack/list.html", partial=partial, **context)
    finally:
        db.close()


@app.post("/ack/<int:id>/confirm", endpoint="ack.confirm")
@roles_required(RoleEnum.READER.value)
def ack_confirm(id: int):
    """Mark an acknowledgement as confirmed."""
    user = session.get("user")
    if not user:
        return jsonify(error="user not logged in"), 401
    user_id = user.get("id")
    db = get_session()
    try:
        ack = (
            db.query(Acknowledgement)
            .filter_by(id=id, user_id=user_id)
            .first()
        )
        if not ack:
            return jsonify(error="acknowledgement not found"), 404
        if ack.acknowledged_at is None:
            ack.acknowledged_at = datetime.utcnow()
            db.commit()
            log_action(user_id, ack.doc_id, "ack_confirm")

            tr = (
                db.query(TrainingResult)
                .filter_by(user_id=user_id, ack_id=id)
                .first()
            )
            if tr and not tr.passed:
                tr.passed = True
                tr.completed_at = datetime.utcnow()
                db.commit()
        counts = _compute_counts(db, user_id, session.get("roles", []))
        new_count = counts["acknowledgements"]

        resp = make_response(jsonify(ok=True))
        resp.headers["HX-Trigger"] = json.dumps({"ackCount": new_count, "showToast": "Acknowledged"})
        broadcast_counts()
        return resp
    finally:
        db.close()


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
        tags = request.args.getlist("tags")
        if tags:
            query = query.filter(and_(*[Document.tags.contains(t) for t in tags]))
            filters["tags"] = tags

        pending = []
        for doc in query.order_by(Document.id).all():
            ack = (
                db.query(Acknowledgement)
                .filter_by(user_id=user_id, doc_id=doc.id)
                .first()
            )
            if not ack or ack.acknowledged_at is None:
                pending.append(doc)

        remaining = len(pending)
        context = {
            "documents": pending,
            "remaining": remaining,
            "filters": filters,
        }
        partial = bool(request.headers.get("HX-Request"))
        context["breadcrumbs"] = [
            {"title": "Home", "url": url_for("dashboard")},
            {"title": "Acknowledgements"},
        ]
        return render_template("acknowledgements.html", partial=partial, **context)
    finally:
        db.close()


@app.route("/notifications/panel", methods=["GET", "POST"])
@roles_required(RoleEnum.READER.value)
def notifications_panel():
    user = session.get("user")
    if not user:
        return "", 401
    user_id = user["id"]
    page = request.args.get("page", 1, type=int)
    db = get_session()
    try:
        if request.method == "POST":
            notif_id = request.form.get("id", type=int)
            if notif_id:
                notif = db.get(Notification, notif_id)
                if notif and notif.user_id == user_id:
                    notif.read = True
                    db.commit()
        per_page = 10
        query = (
            db.query(Notification)
            .filter_by(user_id=user_id)
            .order_by(Notification.created_at.desc())
        )
        notifications = query.offset((page - 1) * per_page).limit(per_page + 1).all()
        has_more = len(notifications) > per_page
        notifications = notifications[:per_page]
        return render_template(
            "partials/_notifications_panel.html",
            notifications=notifications,
            page=page,
            has_more=has_more,
        )
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
            if not ack or ack.acknowledged_at is None:
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
            {"title": "Home", "url": url_for("dashboard")},
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


@app.route("/permissions", methods=["GET", "POST"])
@roles_required(RoleEnum.QUALITY_ADMIN.value)
def manage_permissions():
    db = get_session()
    q = request.values.get("q", "")
    try:
        query = (
            db.query(DocumentPermission)
            .outerjoin(Document)
            .join(Role)
        )
        if q:
            like = f"%{q}%"
            query = query.filter(or_(Document.title.ilike(like), DocumentPermission.folder.ilike(like)))
        perms = query.all()
        if request.method == "POST":
            perm_id = int(request.form.get("perm_id"))
            perm = db.get(DocumentPermission, perm_id)
            if perm:
                perm.can_download = bool(request.form.get("can_download"))
                db.commit()
            return redirect(url_for("manage_permissions", q=q))
        return render_template(
            "permissions.html",
            permissions=perms,
            search=q,
            breadcrumbs=[
                {"title": "Home", "url": url_for("dashboard")},
                {"title": "Permissions"},
            ],
        )
    finally:
        db.close()


@app.get("/training/<int:id>")
@roles_required(RoleEnum.READER.value)
def training_quiz(id: int):
    user = session.get("user")
    if not user:
        return redirect(url_for("auth.login"))
    user_id = user.get("id")
    db = get_session()
    try:
        doc = db.get(Document, id)
        if not doc:
            return "Document not found", 404
        ack = (
            db.query(Acknowledgement)
            .filter_by(doc_id=id, user_id=user_id)
            .first()
        )
        if not ack:
            return "Acknowledgement not found", 404
        doc_data = {"id": doc.id, "title": doc.title}
    finally:
        db.close()
    context = {
        "doc": doc_data,
        "questions": quiz_questions(),
        "breadcrumbs": [
            {"title": "Home", "url": url_for("dashboard")},
            {"title": "Training"},
        ],
    }
    return render_template("training/quiz.html", **context)


@app.post("/training/<int:id>/submit")
@roles_required(RoleEnum.READER.value)
def training_submit(id: int):
    user = session.get("user")
    if not user:
        return redirect(url_for("auth.login"))
    user_id = user.get("id")
    answers = request.form.to_dict()
    total = len(QUIZ_ANSWERS)
    correct = sum(1 for q, a in QUIZ_ANSWERS.items() if answers.get(q) == a)
    incorrect = total - correct
    success_rate = (correct / total * 100) if total else 0
    passed = correct == total
    db = get_session()
    try:
        doc = db.get(Document, id)
        if not doc:
            return "Document not found", 404
        ack = (
            db.query(Acknowledgement)
            .filter_by(doc_id=id, user_id=user_id)
            .first()
        )
        if not ack:
            return "Acknowledgement not found", 404
        tr = TrainingResult(
            user_id=user_id,
            score=correct,
            max_score=total,
            incorrect=incorrect,
            success_rate=success_rate,
            passed=passed,
            ack_id=ack.id,
        )
        db.add(tr)
        if passed and ack.acknowledged_at is None:
            ack.acknowledged_at = datetime.utcnow()
        db.commit()
        doc_data = {"id": doc.id, "title": doc.title}
    finally:
        db.close()
    log_action(user_id, doc_data["id"], "training_submit")
    notify_user(
        user_id,
        "Training result",
        f"You {'passed' if passed else 'failed'} the training for document {doc_data['title']}.",
    )
    if passed:
        broadcast_counts()
        return redirect(url_for("acknowledgements"))
    return render_template(
        "training/quiz.html",
        doc=doc_data,
        questions=quiz_questions(),
        error="Please try again",
        breadcrumbs=[
            {"title": "Home", "url": url_for("dashboard")},
            {"title": "Training"},
        ],
    )


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
    incorrect = len(correct) - score
    success_rate = (score / len(correct) * 100) if correct else 0
    passed = score == len(correct)
    session = get_session()
    try:
        session.add(
            TrainingResult(
                user_id=user_id,
                score=score,
                max_score=len(correct),
                incorrect=incorrect,
                success_rate=success_rate,
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
            {"title": "Home", "url": url_for("dashboard")},
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
    pdf, _, _ = render_form_and_store(form_name, fields)
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
