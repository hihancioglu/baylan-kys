import { showToast } from '../components/toast.js';

document.querySelectorAll('[data-errors]').forEach(el => {
  try {
    const errors = JSON.parse(el.dataset.errors || '{}');
    Object.values(errors).flat().forEach(msg => showToast(msg, { timeout: 6000 }));
  } catch (e) {
    console.error('Failed to parse errors', e);
  }
});

const saveDraftBtn = document.getElementById('save-draft');
if (saveDraftBtn) {
  const messages = {
    fileNotUploaded: saveDraftBtn.dataset.fileNotUploaded,
    sessionEnded: saveDraftBtn.dataset.sessionEnded,
    documentUploaded: saveDraftBtn.dataset.documentUploaded,
    documentCreateError: saveDraftBtn.dataset.documentCreateError,
  };

  saveDraftBtn.addEventListener('click', async () => {
    const data = {
      code: saveDraftBtn.dataset.code,
      title: saveDraftBtn.dataset.title,
      department: saveDraftBtn.dataset.department,
      process: saveDraftBtn.dataset.process,
      standard: saveDraftBtn.dataset.standard,
      tags: saveDraftBtn.dataset.tags.split(',').map(t => t.trim()).filter(Boolean),
      template: saveDraftBtn.dataset.template,
      uploaded_file_key: saveDraftBtn.dataset.uploadedFileKey,
      uploaded_file_name: saveDraftBtn.dataset.uploadedFileName
    };
    if (!data.uploaded_file_key) {
      showToast(messages.fileNotUploaded, { timeout: 6000 });
      return;
    }
    const csrf = document
      .querySelector('meta[name="csrf-token"]')
      .getAttribute('content');
    const response = await fetch('/api/documents', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'X-CSRFToken': csrf
      },
      body: JSON.stringify(data)
    });
    if (response.status === 403) {
      showToast(messages.sessionEnded, { timeout: 6000 });
      return;
    }
    const result = await response.json();
    if (result.id) {
      showToast(messages.documentUploaded);
      window.location = `/documents/${result.id}?created=1`;
    } else if (result.errors) {
      Object.values(result.errors).forEach(msg => showToast(msg, { timeout: 6000 }));
    } else {
      showToast(messages.documentCreateError, { timeout: 6000 });
    }
  });
}
