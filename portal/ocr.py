import textract


def extract_text(file_path: str) -> str:
    """Extract text from a PDF or Office document using textract."""
    try:
        text = textract.process(file_path)
        return text.decode("utf-8")
    except Exception:
        return ""
