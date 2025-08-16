from io import BytesIO
from typing import List, Dict, Tuple, Optional

from datetime import datetime
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


def revision_report(start: Optional[datetime] = None, end: Optional[datetime] = None) -> List[Dict]:
    session = get_session()
    try:
        query = session.query(DocumentRevision).join(Document)
        if start:
            query = query.filter(DocumentRevision.created_at >= start)
        if end:
            query = query.filter(DocumentRevision.created_at <= end)
        rows = [
            {
                "document": r.document.title,
                "major": r.major_version,
                "minor": r.minor_version,
                "created_at": r.created_at.isoformat(),
            }
            for r in query.all()
        ]
    finally:
        session.close()
    return rows


def training_compliance_report(
    start: Optional[datetime] = None, end: Optional[datetime] = None
) -> List[Dict]:
    session = get_session()
    try:
        query = session.query(TrainingResult).join(User)
        if start:
            query = query.filter(TrainingResult.completed_at >= start)
        if end:
            query = query.filter(TrainingResult.completed_at <= end)
        rows = [
            {
                "user": t.user.username,
                "score": t.score,
                "passed": t.passed,
                "completed_at": t.completed_at.isoformat(),
            }
            for t in query.all()
        ]
    finally:
        session.close()
    return rows


def pending_approvals_report(
    start: Optional[datetime] = None, end: Optional[datetime] = None
) -> List[Dict]:
    session = get_session()
    try:
        query = (
            session.query(WorkflowStep)
            .join(Document)
            .filter(WorkflowStep.status == "Pending")
        )
        if start:
            query = query.filter(Document.created_at >= start)
        if end:
            query = query.filter(Document.created_at <= end)
        rows = [
            {
                "document": s.document.title,
                "step_order": s.step_order,
                "approver": s.approver,
                "created_at": s.document.created_at.isoformat(),
            }
            for s in query.all()
        ]
    finally:
        session.close()
    return rows


def build_report(
    kind: str, fmt: str, start: Optional[datetime] = None, end: Optional[datetime] = None
) -> Tuple[bytes, str, str]:
    if kind == "revisions":
        rows = revision_report(start, end)
    elif kind == "training":
        rows = training_compliance_report(start, end)
    elif kind == "pending-approvals":
        rows = pending_approvals_report(start, end)
    else:
        raise ValueError("unknown report type")
    return _render_output(rows, fmt)
