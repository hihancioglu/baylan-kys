import 'bootstrap';
document.addEventListener('showToast', (event) => {
  const toastEl = document.getElementById('action-toast');
  if (!toastEl) return;
  toastEl.querySelector('.toast-body').textContent = event.detail;
  const toast = bootstrap.Toast.getOrCreateInstance(toastEl);
  toast.show();
});
console.log('app loaded');
