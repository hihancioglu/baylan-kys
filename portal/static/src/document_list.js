import { getToken } from './tokens';
getToken('color-primary');

document.addEventListener('htmx:afterSwap', function (evt) {
  if (evt.target.id === 'document-table') {
    window.scrollTo(0, 0);
  }
});
