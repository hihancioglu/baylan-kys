import os
import subprocess
from datetime import datetime
from typing import Optional

import requests

from models import SignatureLog, get_session

HSM_API_URL = os.environ.get("HSM_API_URL", "http://hsm.example.com/sign")


def convert_to_pdf(source_path: str, output_dir: Optional[str] = None) -> str:
    """Convert a document to PDF using LibreOffice/OnlyOffice."""
    out_dir = output_dir or os.path.dirname(source_path) or "."
    subprocess.run(
        [
            "libreoffice",
            "--headless",
            "--convert-to",
            "pdf",
            source_path,
            "--outdir",
            out_dir,
        ],
        check=True,
    )
    base = os.path.splitext(os.path.basename(source_path))[0]
    return os.path.join(out_dir, f"{base}.pdf")


def sign_pdf_with_hsm(pdf_path: str, user_id: int, doc_id: int) -> bytes:
    """Send a PDF to the HSM service provider for digital signing."""
    with open(pdf_path, "rb") as f:
        response = requests.post(HSM_API_URL, files={"document": f}, data={"user_id": user_id})
    response.raise_for_status()
    session = get_session()
    try:
        session.add(SignatureLog(user_id=user_id, doc_id=doc_id, signed_at=datetime.utcnow()))
        session.commit()
    finally:
        session.close()
    return response.content


def create_signed_pdf(
    doc_id: int,
    user_id: int,
    source_path: str,
    output_dir: Optional[str] = None,
) -> bytes:
    """Convert a document to PDF and obtain a digital signature from the HSM service."""
    pdf_path = convert_to_pdf(source_path, output_dir)
    return sign_pdf_with_hsm(pdf_path, user_id, doc_id)
