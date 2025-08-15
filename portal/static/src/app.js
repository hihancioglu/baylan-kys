import 'bootstrap';
document.addEventListener('showToast', (event) => {
  const toastEl = document.getElementById('action-toast');
  if (!toastEl) return;
  toastEl.querySelector('.toast-body').textContent = event.detail;
  const toast = bootstrap.Toast.getOrCreateInstance(toastEl);
  toast.show();
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
