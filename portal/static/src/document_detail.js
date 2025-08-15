document.addEventListener('DOMContentLoaded', () => {
  const tabs = document.querySelectorAll('#document-tabs .nav-link');
  const metadata = document.getElementById('tab-metadata');
  const versions = document.getElementById('tab-versions');

  tabs.forEach((tab) => {
    tab.addEventListener('click', (evt) => {
      evt.preventDefault();
      tabs.forEach((t) => t.classList.remove('active'));
      tab.classList.add('active');
      if (tab.dataset.tab === 'metadata') {
        metadata.classList.remove('d-none');
        versions.classList.add('d-none');
      } else {
        versions.classList.remove('d-none');
        metadata.classList.add('d-none');
      }
    });
  });
});

document.addEventListener('htmx:afterSwap', (evt) => {
  if (evt.target.id === 'version-area') {
    window.scrollTo(0, 0);
  }
});
