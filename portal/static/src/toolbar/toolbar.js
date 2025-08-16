import { getToken } from '../tokens.js';
getToken('color-primary');

export function initToolbar(el) {
  if (!el) return;
  const filterBtn = el.querySelector('[data-action="filter"]');
  if (filterBtn) {
    filterBtn.addEventListener('click', () => {
      const panel = document.querySelector('[data-component="filters"]');
      if (panel) {
        panel.classList.toggle('d-none');
      }
    });
  }
}

document.addEventListener('DOMContentLoaded', () => {
  document.querySelectorAll('[data-component="toolbar"]').forEach(initToolbar);
});

export default { initToolbar };
