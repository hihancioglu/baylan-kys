import os
from pdfminer.high_level import extract_text as pdf_extract_text
from docx import Document


def extract_text(file_path: str) -> str:
    """Extract text from a PDF or DOCX document."""
    try:
        ext = os.path.splitext(file_path)[1].lower()
        if ext == ".pdf":
            return pdf_extract_text(file_path)
        if ext == ".docx":
            doc = Document(file_path)
            return "\n".join(p.text for p in doc.paragraphs)
        return ""
    except Exception:
        return ""
