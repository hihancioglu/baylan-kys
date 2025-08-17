import { getToken } from './tokens.js';
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
  if (!checkboxes.length) return;
  const update = () => {
    if (!summary || !compareBtn) return;
    summary.innerHTML = '';
    const selected = Array.from(checkboxes).filter((cb) => cb.checked);
    selected.forEach((cb) => {
      const li = document.createElement('li');
      li.className = 'list-group-item';
      li.textContent = cb.dataset.label;
      summary.appendChild(li);
    });
    if (selected.length >= 2) {
      compareBtn.disabled = false;
      compareBtn.classList.remove('btn-secondary');
      compareBtn.classList.add('btn-primary');
    } else {
      compareBtn.disabled = true;
      compareBtn.classList.remove('btn-primary');
      compareBtn.classList.add('btn-secondary');
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
        alert('Select another version to compare.');
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
    const csrf = data.get('csrf_token');
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

document.addEventListener('DOMContentLoaded', () => {
  initTabs();
  initVersionSelection();
  initWorkflowForm();
});

document.addEventListener('htmx:afterSwap', (evt) => {
  if (evt.target.id === 'tab-versions' || evt.target.id === 'revision-panel') {
    initVersionSelection();
    if (evt.target.id === 'tab-versions') {
      window.scrollTo(0, 0);
    }
  }
});
