import { getToken } from './tokens.js';
// Bootstrap JavaScript is loaded globally via CDN in the base template,
// so there's no need for an ES module import here.
getToken('color-primary');

document.addEventListener('DOMContentLoaded', () => {
  document
    .querySelectorAll('[data-bs-toggle="tooltip"]')
    .forEach((el) => new bootstrap.Tooltip(el));
});

function displayToast(message) {
  const toastEl = document.getElementById('action-toast');
  if (!toastEl) return;
  toastEl.querySelector('.toast-body').textContent = message;
  const toast = window.bootstrap.Toast.getOrCreateInstance(toastEl);
  toast.show();
}

document.addEventListener('showToast', (event) => {
  displayToast(event.detail);
});

document.addEventListener('ackCount', (event) => {
  const el = document.getElementById('ack-count');
  if (el) el.textContent = event.detail;
});

document.body.addEventListener('htmx:responseError', (event) => {
  displayToast(event.detail.xhr.response || 'Request failed');
  if (event.detail.target) {
    event.detail.target.innerHTML = '';
  }
});

document.body.addEventListener('htmx:sendError', () => {
  displayToast('Request failed');
});

document.body.addEventListener('htmx:beforeRequest', (event) => {
  const target = event.detail.target;
  const tmpl = document.getElementById('skeleton-template');
  if (target && tmpl) {
    target.innerHTML = tmpl.innerHTML;
  }
});

document.body.addEventListener('htmx:afterSwap', (event) => {
  const target = event.detail.target;
  if (target && !target.innerHTML.trim()) {
    target.innerHTML = '<div class="text-muted text-center py-5">No content available.</div>';
  }
});

console.log('app loaded');
