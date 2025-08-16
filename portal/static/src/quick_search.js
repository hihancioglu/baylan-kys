const mockDocs = [
  { title: 'Quality Manual v1', url: '/documents/1' },
  { title: 'Safety Procedure v2', url: '/documents/2' },
  { title: 'HR Policy v3', url: '/documents/3' },
  { title: 'Document Control 1.0', url: '/documents/4' }
];

function filterDocs(query) {
  if (!query) return [];
  query = query.toLowerCase();
  return mockDocs.filter(d => d.title.toLowerCase().includes(query));
}

function highlight(text, query) {
  if (!query) return text;
  const re = new RegExp(`(${query})`, 'ig');
  return text.replace(re, '<mark>$1</mark>');
}

const panel = document.getElementById('quick-search-panel');
const input = document.getElementById('quick-search-input');
const resultsEl = document.getElementById('quick-search-results');
let activeIndex = -1;
let currentResults = [];

function openPanel() {
  panel.classList.remove('d-none');
  input.value = '';
  resultsEl.innerHTML = '';
  activeIndex = -1;
  currentResults = [];
  input.focus();
}

function closePanel() {
  panel.classList.add('d-none');
}

document.addEventListener('keydown', (e) => {
  if (e.ctrlKey && e.key === '/') {
    e.preventDefault();
    openPanel();
  } else if (e.key === 'Escape' && !panel.classList.contains('d-none')) {
    closePanel();
  }
});

input.addEventListener('input', (e) => {
  const q = e.target.value.trim();
  const start = performance.now();
  currentResults = filterDocs(q);
  activeIndex = -1;
  renderResults(q);
  const elapsed = performance.now() - start;
  if (elapsed > 150) {
    console.warn('Search took longer than expected:', elapsed);
  }
});

function renderResults(query) {
  resultsEl.innerHTML = currentResults
    .map((doc, idx) => `<li class="list-group-item ${idx === activeIndex ? 'active' : ''}" data-index="${idx}" data-url="${doc.url}">${highlight(doc.title, query)}</li>`)
    .join('');
}

input.addEventListener('keydown', (e) => {
  if (e.key === 'ArrowDown') {
    e.preventDefault();
    if (activeIndex < currentResults.length - 1) {
      activeIndex++;
      renderResults(input.value.trim());
    }
  } else if (e.key === 'ArrowUp') {
    e.preventDefault();
    if (activeIndex > 0) {
      activeIndex--;
      renderResults(input.value.trim());
    }
  } else if (e.key === 'Enter') {
    const selected = currentResults[activeIndex];
    if (selected) {
      window.location.href = selected.url;
    }
  }
});

resultsEl.addEventListener('click', (e) => {
  const li = e.target.closest('li[data-index]');
  if (li) {
    window.location.href = li.dataset.url;
  }
});

panel.addEventListener('click', (e) => {
  if (e.target === panel) {
    closePanel();
  }
});
