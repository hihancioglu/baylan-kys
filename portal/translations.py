from __future__ import annotations

from flask import has_request_context, request

TRANSLATIONS = {
    "en": {
        "new_document_step3_title": "New Document - Step 3",
        "generation_failed": "Generation failed: {error}",
        "document_generated_success": "Document generated successfully.",
        "upload_failed": "Upload failed: {error}",
        "file_uploaded_success": "File uploaded successfully.",
        "file_too_large": "File too large.",
        "unsupported_file_type": "Unsupported file type.",
        "view_document": "View Document",
        "create": "Create",
        "save_draft": "Save as Draft",
        "cancel": "Cancel",
        "file_not_uploaded": "File could not be uploaded",
        "session_ended": "Your session has ended. Please refresh the page.",
        "document_uploaded_for_approval": (
            "Document uploaded successfully and sent for approval"
        ),
        "document_create_error": (
            "An error occurred while creating the document"
        ),
        "code_label": "Code",
        "title_label": "Title",
        "department_label": "Department",
        "type_label": "Type",
        "standard_label": "Standard",
        "no_versions_yet": "No versions uploaded yet.",
        "upload_new_version": "Upload New Version",
        "audit_create": "Created",
        "audit_view": "Viewed",
        "audit_download_document": "Document downloaded",
        "audit_download_revision": "Revision downloaded",
        "audit_version_uploaded": "Version uploaded",
        "audit_publish_document": "Document published",
        "audit_assign_mr": "MR assigned",
        "audit_checkout_document": "Document checked out",
        "audit_checkin_document": "Document checked in",
        "audit_rollback": "Rolled back",
    },
    "tr": {
        "new_document_step3_title": "Yeni Doküman - Adım 3",
        "generation_failed": "Oluşturma başarısız: {error}",
        "document_generated_success": "Doküman başarıyla oluşturuldu.",
        "upload_failed": "Yükleme başarısız: {error}",
        "file_uploaded_success": "Dosya başarıyla yüklendi.",
        "file_too_large": "Dosya çok büyük.",
        "unsupported_file_type": "Desteklenmeyen dosya türü.",
        "view_document": "Dokümanı Görüntüle",
        "create": "Oluştur",
        "save_draft": "Taslak olarak kaydet",
        "cancel": "İptal",
        "file_not_uploaded": "Dosya yüklenemedi",
        "session_ended": "Oturumunuz sonlandı. Lütfen sayfayı yenileyin.",
        "document_uploaded_for_approval": (
            "Doküman başarıyla yüklendi ve onaya gönderildi"
        ),
        "document_create_error": (
            "Doküman oluşturulurken bir hata oluştu"
        ),
        "code_label": "Kod",
        "title_label": "Başlık",
        "department_label": "Departman",
        "type_label": "Tür",
        "standard_label": "Standart",
        "no_versions_yet": "Henüz sürüm yüklenmedi.",
        "upload_new_version": "Yeni Sürüm Yükle",
        "audit_create": "Oluşturuldu",
        "audit_view": "Görüntülendi",
        "audit_download_document": "Doküman indirildi",
        "audit_download_revision": "Revizyon indirildi",
        "audit_version_uploaded": "Sürüm yüklendi",
        "audit_publish_document": "Doküman yayımlandı",
        "audit_assign_mr": "MR atandı",
        "audit_checkout_document": "Doküman check-out yapıldı",
        "audit_checkin_document": "Doküman check-in yapıldı",
        "audit_rollback": "Geri alındı",
    },
}


def get_locale() -> str:
    if has_request_context():
        return request.cookies.get("pref-language", "en")
    return "en"


def t(key: str, **kwargs: str) -> str:
    locale = get_locale()
    # Look up translation in the requested locale, fall back to English, then the key
    text = TRANSLATIONS.get(locale, {}).get(key, TRANSLATIONS["en"].get(key, key))
    try:
        return text.format(**kwargs)
    except Exception:
        return text
