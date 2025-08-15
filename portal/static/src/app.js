import { getToken } from './tokens';
import 'bootstrap';
getToken('color-primary');

function displayToast(message) {
  const toastEl = document.getElementById('action-toast');
  if (!toastEl) return;
  toastEl.querySelector('.toast-body').textContent = message;
  const toast = bootstrap.Toast.getOrCreateInstance(toastEl);
  toast.show();
}

document.addEventListener('showToast', (event) => {
  displayToast(event.detail);
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

function connectEvents() {
  const evt = new EventSource('/events');
  evt.onmessage = (e) => {
    try {
      const data = JSON.parse(e.data);
      const approvalEl = document.getElementById('approval-count');
      if (approvalEl) approvalEl.textContent = data.approvals;
      const ackEl = document.getElementById('ack-count');
      if (ackEl) ackEl.textContent = data.acknowledgements;
    } catch (err) {
      console.error('Failed to parse event', err);
    }
  };
  evt.onerror = () => {
    evt.close();
    setTimeout(connectEvents, 1000);
  };
}

connectEvents();
