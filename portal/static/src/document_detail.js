import { getToken } from './tokens.js';
import { showToast } from './components/toast.js';
getToken('color-primary');

function initTabs() {
  const tabs = document.querySelectorAll('#document-tabs .nav-link');
  const panels = {
    summary: document.getElementById('tab-summary'),
    versions: document.getElementById('tab-versions'),
    notes: document.getElementById('tab-notes'),
    relations: document.getElementById('tab-relations'),
  };
  const activate = (name) => {
    tabs.forEach((t) => t.classList.remove('active'));
    Object.values(panels).forEach((p) => p.classList.add('d-none'));
    const current = Array.from(tabs).find((t) => t.dataset.tab === name) || tabs[0];
    current.classList.add('active');
    panels[name].classList.remove('d-none');
  };
  tabs.forEach((tab) => {
    tab.addEventListener('click', (evt) => {
      evt.preventDefault();
      activate(tab.dataset.tab);
      history.replaceState(null, '', `#${tab.dataset.tab}`);
    });
  });
  const hash = window.location.hash.replace('#', '');
  if (panels[hash]) {
    activate(hash);
  }
}

function initVersionSelection() {
  const checkboxes = document.querySelectorAll('#tab-versions .version-checkbox');
  const summary = document.getElementById('selected-versions');
  const compareBtn = document.getElementById('compare-button');
  const compareToBtn = document.getElementById('compare-to-button');
  const downloadA = document.getElementById('download-rev-a');
  const downloadB = document.getElementById('download-rev-b');
  const form = document.getElementById('version-list');
  const docId = form?.action.match(/\/documents\/(\d+)\/compare/)?.[1];
  let revA = null;
  let revB = null;
  const hasServerDiff = !compareBtn?.dataset.bsTarget;
  if (!hasServerDiff && compareBtn) {
    compareBtn.addEventListener('click', () => {
      if (compareBtn.disabled) return;
      const modalEl = document.getElementById('local-compare-modal');
      if (modalEl) {
        const modal =
          bootstrap.Modal.getInstance(modalEl) ||
          new bootstrap.Modal(modalEl);
        modal.show();
      }
    });
  }
  if (!checkboxes.length) return;
  const update = () => {
    if (!summary || !compareBtn) return;
    summary.innerHTML = '';
    const selected = Array.from(checkboxes).filter((cb) => cb.checked);
    revA = selected[0]?.value || null;
    revB = selected[1]?.value || null;
    selected.forEach((cb) => {
      const li = document.createElement('li');
      li.className = 'list-group-item';
      li.textContent = cb.dataset.label;
      summary.appendChild(li);
    });
    if (selected.length === 2) {
      compareBtn.disabled = false;
      compareBtn.classList.remove('btn-secondary');
      compareBtn.classList.add('btn-primary');
      if (downloadA && downloadB && docId && revA && revB) {
        downloadA.classList.remove('d-none');
        downloadB.classList.remove('d-none');
        downloadA.href = `/documents/${docId}/revisions/${revA}/download`;
        downloadB.href = `/documents/${docId}/revisions/${revB}/download`;
        downloadA.textContent = `Download ${selected[0].dataset.label}`;
        downloadB.textContent = `Download ${selected[1].dataset.label}`;
      }
    } else {
      compareBtn.disabled = true;
      compareBtn.classList.remove('btn-primary');
      compareBtn.classList.add('btn-secondary');
      if (downloadA && downloadB) {
        downloadA.classList.add('d-none');
        downloadB.classList.add('d-none');
        downloadA.removeAttribute('href');
        downloadB.removeAttribute('href');
      }
    }
  };
  checkboxes.forEach((cb) => cb.addEventListener('change', update));
  update();

  if (compareToBtn) {
    const currentRevId = compareToBtn.dataset.revId;
    const compareUrl = compareToBtn.dataset.url;
    compareToBtn.addEventListener('click', () => {
      const other = Array.from(checkboxes).filter(
        (cb) => cb.checked && cb.value !== currentRevId
      );
      if (other.length !== 1) {
        showToast('Karşılaştırılacak başka bir sürüm seçin');
        return;
      }
      const url = new URL(compareUrl, window.location.origin);
      url.searchParams.append('rev_id', currentRevId);
      url.searchParams.append('rev_id', other[0].value);
      window.location.href = url.toString();
    });
  }
}

function initWorkflowForm() {
  const form = document.getElementById('workflow-form');
  if (!form) return;
  form.addEventListener('submit', async (evt) => {
    evt.preventDefault();
    const data = new FormData(form);
    const payload = {
      doc_id: data.get('doc_id'),
      reviewers: data.getAll('reviewers[]'),
      approvers: data.getAll('approvers[]'),
    };
    const csrf = document
      .querySelector('meta[name="csrf-token"]')
      .getAttribute('content');
    await fetch('/api/workflow/start', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'X-CSRFToken': csrf,
      },
      body: JSON.stringify(payload),
    });
  });
}

function initAssignForm() {
  const form = document.getElementById('assign-form');
  if (!form) return;
  form.addEventListener('htmx:configRequest', (evt) => {
    const docId = form.querySelector('input[name="doc_id"]').value;
    const targets = Array.from(
      form.querySelectorAll('input[name="targets"]:checked')
    ).map((cb) => cb.value);
    const csrf = document
      .querySelector('meta[name="csrf-token"]')
      .getAttribute('content');
    evt.detail.headers['Content-Type'] = 'application/json';
    evt.detail.headers['X-CSRFToken'] = csrf;
    evt.detail.parameters = {};
    evt.detail.body = JSON.stringify({ doc_id: docId, targets });
    form.dataset.lastCount = targets.length;
  });
  form.addEventListener('htmx:afterRequest', (evt) => {
    if (evt.detail.successful) {
      const modalEl = document.getElementById('assignModal');
      const modal =
        bootstrap.Modal.getInstance(modalEl) ||
        new bootstrap.Modal(modalEl);
      modal.hide();
      form.reset();
      const badge = document.getElementById('assignment-count');
      if (badge) {
        const add = parseInt(form.dataset.lastCount || '0', 10);
        const current = parseInt(badge.textContent || '0', 10);
        badge.textContent = current + add;
      }
    } else {
      let message = 'Assignment failed';
      try {
        const data = JSON.parse(evt.detail.xhr.responseText);
        if (data && data.error) {
          message = data.error;
        }
      } catch (e) {
        // ignore
      }
      showToast(message, { timeout: 6000 });
    }
  });
}

document.addEventListener('DOMContentLoaded', () => {
  initTabs();
  initVersionSelection();
  initWorkflowForm();
  initAssignForm();

  const params = new URLSearchParams(window.location.search);
  if (params.get('created') === '1') {
    showToast('Doküman başarıyla yüklendi ve onaya gönderildi');
    params.delete('created');
    const url = `${window.location.pathname}${params.toString() ? `?${params.toString()}` : ''}${window.location.hash}`;
    history.replaceState(null, '', url);
  }
});

document.addEventListener('htmx:afterSwap', (evt) => {
  if (evt.target.id === 'tab-versions' || evt.target.id === 'revision-panel') {
    initVersionSelection();
    if (evt.target.id === 'tab-versions') {
      window.scrollTo(0, 0);
    }
  }
});
document.body.addEventListener('auto-review-started', () => {
  showToast('Doküman incelemeye gönderildi');
  const btn = document.getElementById('publish-button');
  if (btn) {
    btn.disabled = true;
    btn.textContent = 'Publish (Approval pending)';
  }
});
