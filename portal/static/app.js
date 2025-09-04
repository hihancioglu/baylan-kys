import { getToken } from './tokens.js';
import { showToast } from './components/toast.js';
// Bootstrap JavaScript is loaded globally via CDN in the base template,
// so there's no need for an ES module import here.
getToken('color-primary');

document.addEventListener('DOMContentLoaded', () => {
  document
    .querySelectorAll('[data-bs-toggle="tooltip"]')
    .forEach((el) => new bootstrap.Tooltip(el));
});

document.addEventListener('showToast', (event) => {
  showToast(event.detail);
});

document.addEventListener('ackCount', (event) => {
  const el = document.getElementById('ack-count');
  if (el) el.textContent = event.detail;
});

document.body.addEventListener('htmx:responseError', (event) => {
  let message = 'Request failed';
  try {
    const data = JSON.parse(event.detail.xhr.responseText);
    if (data && data.error) {
      message = data.error;
    }
  } catch (e) {
    if (event.detail.xhr.responseText) {
      message = event.detail.xhr.responseText;
    }
  }
  showToast(message, { timeout: 6000 });
  if (event.detail.target) {
    event.detail.target.innerHTML = '';
  }
});

document.body.addEventListener('htmx:sendError', () => {
  showToast('Request failed', { timeout: 6000 });
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
