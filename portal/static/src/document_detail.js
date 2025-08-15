function initTabs() {
  const tabs = document.querySelectorAll('#document-tabs .nav-link');
  const panels = {
    summary: document.getElementById('tab-summary'),
    versions: document.getElementById('tab-versions'),
    related: document.getElementById('tab-related'),
  };
  tabs.forEach((tab) => {
    tab.addEventListener('click', (evt) => {
      evt.preventDefault();
      tabs.forEach((t) => t.classList.remove('active'));
      tab.classList.add('active');
      Object.values(panels).forEach((p) => p.classList.add('d-none'));
      panels[tab.dataset.tab].classList.remove('d-none');
    });
  });
}

document.addEventListener('DOMContentLoaded', initTabs);

document.addEventListener('htmx:afterSwap', (evt) => {
  if (evt.target.id === 'version-area') {
    initTabs();
    window.scrollTo(0, 0);
  }
});
