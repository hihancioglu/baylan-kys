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
        query = (
            session.query(
                Document.title,
                DocumentRevision.major_version,
                DocumentRevision.minor_version,
                DocumentRevision.created_at,
            )
            .join(Document)
            .order_by(None)
        )
        if start:
            query = query.filter(DocumentRevision.created_at >= start)
        if end:
            query = query.filter(DocumentRevision.created_at <= end)
        results = query.all()
        return [
            {
                "document": title,
                "major": major,
                "minor": minor,
                "created_at": created.isoformat(),
            }
            for title, major, minor, created in results
        ]
    finally:
        session.close()


def training_compliance_report(
    start: Optional[datetime] = None, end: Optional[datetime] = None
) -> List[Dict]:
    session = get_session()
    try:
        query = (
            session.query(
                User.username,
                TrainingResult.score,
                TrainingResult.passed,
                TrainingResult.completed_at,
            )
            .join(User)
            .order_by(None)
        )
        if start:
            query = query.filter(TrainingResult.completed_at >= start)
        if end:
            query = query.filter(TrainingResult.completed_at <= end)
        results = query.all()
        return [
            {
                "user": username,
                "score": score,
                "passed": passed,
                "completed_at": completed.isoformat(),
            }
            for username, score, passed, completed in results
        ]
    finally:
        session.close()


def pending_approvals_report(
    start: Optional[datetime] = None, end: Optional[datetime] = None
) -> List[Dict]:
    session = get_session()
    try:
        query = (
            session.query(
                Document.title,
                WorkflowStep.step_order,
                WorkflowStep.approver,
                Document.created_at,
            )
            .join(Document)
            .filter(WorkflowStep.status == "Pending")
            .order_by(None)
        )
        if start:
            query = query.filter(Document.created_at >= start)
        if end:
            query = query.filter(Document.created_at <= end)
        results = query.all()
        return [
            {
                "document": title,
                "step_order": step_order,
                "approver": approver,
                "created_at": created.isoformat(),
            }
            for title, step_order, approver, created in results
        ]
    finally:
        session.close()


def build_report(
    kind: str, fmt: str, start: Optional[datetime] = None, end: Optional[datetime] = None
) -> Tuple[bytes, str, str]:
    mapping = {
        "revisions": revision_report,
        "training": training_compliance_report,
        "pending-approvals": pending_approvals_report,
    }
    fn = mapping.get(kind)
    if not fn:
        raise ValueError("unknown report type")
    rows = fn(start, end)
    return _render_output(rows, fmt)
