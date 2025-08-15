import os
import json
import requests

# Default OnlyOffice Document Server endpoint
DOCUMENT_SERVER_URL = os.environ.get(
    "DOCUMENT_SERVER_URL", "http://onlyoffice/ConvertService.ashx"
)

# Directory containing DOCXF templates
TEMPLATE_ROOT = os.path.join(os.path.dirname(__file__), "..", "templates", "forms")


def render_form_to_pdf(form_name: str, data: dict | None = None) -> bytes:
    """Render a DOCXF template and return the resulting PDF bytes.

    Parameters
    ----------
    form_name: str
        Name of the form template located under ``templates/forms`` without
        extension.
    data: dict | None
        Optional form field values to be merged.  The data is forwarded to the
        OnlyOffice Document Server; the server is expected to handle the merge.
    """
    template_path = os.path.join(TEMPLATE_ROOT, f"{form_name}.docxf")
    if not os.path.exists(template_path):
        raise FileNotFoundError(f"Template {form_name} not found")

    with open(template_path, "rb") as f:
        files = {
            "file": (f"{form_name}.docxf", f, "application/vnd.openxmlformats-officedocument.wordprocessingml.document"),
        }
        payload = {
            "async": False,
            "filetype": "docxf",
            "outputtype": "pdf",
            "title": form_name,
        }
        # The Document Server expects JSON in a field named 'request'
        data_field = {
            "request": json.dumps(payload),
        }
        if data:
            data_field["data"] = json.dumps(data)
        response = requests.post(DOCUMENT_SERVER_URL, data=data_field, files=files)
    response.raise_for_status()
    return response.content
