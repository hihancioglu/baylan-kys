const lang = localStorage.getItem('pref-language');
if (lang) document.documentElement.lang = lang;
const theme = localStorage.getItem('pref-theme');
if (theme) document.documentElement.setAttribute('data-bs-theme', theme);
const density = localStorage.getItem('pref-density');
if (density) document.documentElement.setAttribute('data-density', density);

const link = document.getElementById('app-css');
if (link) {
  link.addEventListener('load', function() {
    this.rel = 'stylesheet';
  });
}

document.body.addEventListener('htmx:configRequest', (event) => {
  const token = document.querySelector('meta[name="csrf-token"]').getAttribute('content');
  event.detail.headers['X-CSRFToken'] = token;
});
