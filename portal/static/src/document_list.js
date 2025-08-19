import { getToken } from './tokens.js';
import { initFilters } from './filters/index.js';
getToken('color-primary');

document.addEventListener('DOMContentLoaded', () => {
  const form = document.querySelector('[data-component="filters"]');
  initFilters(form);
});

document.addEventListener('htmx:afterSwap', function (evt) {
  if (evt.target.id === 'document-table') {
    window.scrollTo(0, 0);
  }
});

document.addEventListener('click', (e) => {
  const toggle = e.target.closest('.group-toggle');
  if (toggle) {
    const group = toggle.closest('tbody[data-group]');
    if (group) {
      group.classList.toggle('collapsed');
    }
  }
});
