from io import BytesIO
from typing import List, Dict, Tuple

import pandas as pd
from reportlab.lib.pagesizes import letter
from reportlab.pdfgen import canvas

from models import (
    get_session,
    DocumentRevision,
    Document,
    TrainingResult,
    User,
    WorkflowStep,
)


def _df_to_pdf(df: pd.DataFrame) -> bytes:
    """Render a DataFrame to a very basic PDF table."""
    buffer = BytesIO()
    c = canvas.Canvas(buffer, pagesize=letter)
    text = c.beginText(40, 800)
    text.textLine("\t".join(df.columns))
    for _, row in df.iterrows():
        text.textLine("\t".join(str(v) for v in row))
    c.drawText(text)
    c.save()
    buffer.seek(0)
    return buffer.getvalue()


def _render_output(rows: List[Dict], fmt: str) -> Tuple[bytes, str, str]:
    """Return file content, mime type and extension."""
    df = pd.DataFrame(rows)
    if fmt == "csv":
        return df.to_csv(index=False).encode("utf-8"), "text/csv", "csv"
    if fmt == "xlsx":
        buf = BytesIO()
        df.to_excel(buf, index=False)
        return (
            buf.getvalue(),
            "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
            "xlsx",
        )
    if fmt == "pdf":
        pdf_bytes = _df_to_pdf(df)
        return pdf_bytes, "application/pdf", "pdf"
    raise ValueError("unsupported format")


def revision_report() -> List[Dict]:
    session = get_session()
    try:
        rows = [
            {
                "document": r.document.title,
                "major": r.major_version,
                "minor": r.minor_version,
                "created_at": r.created_at.isoformat(),
            }
            for r in session.query(DocumentRevision).join(Document).all()
        ]
    finally:
        session.close()
    return rows


def training_compliance_report() -> List[Dict]:
    session = get_session()
    try:
        rows = [
            {
                "user": t.user.username,
                "score": t.score,
                "passed": t.passed,
                "completed_at": t.completed_at.isoformat(),
            }
            for t in session.query(TrainingResult).join(User).all()
        ]
    finally:
        session.close()
    return rows


def pending_approvals_report() -> List[Dict]:
    session = get_session()
    try:
        rows = [
            {
                "document": s.document.title,
                "step_order": s.step_order,
                "approver": s.approver,
            }
            for s in session.query(WorkflowStep)
            .join(Document)
            .filter(WorkflowStep.status == "Pending")
            .all()
        ]
    finally:
        session.close()
    return rows


def build_report(kind: str, fmt: str) -> Tuple[bytes, str, str]:
    if kind == "revisions":
        rows = revision_report()
    elif kind == "training":
        rows = training_compliance_report()
    elif kind == "pending-approvals":
        rows = pending_approvals_report()
    else:
        raise ValueError("unknown report type")
    return _render_output(rows, fmt)
