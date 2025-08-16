export function createSkeleton(lines = 3) {
  const container = document.createElement('div');
  container.className = 'placeholder-glow';
  for (let i = 0; i < lines; i++) {
    const span = document.createElement('span');
    span.className = 'placeholder col-12 mb-2';
    container.appendChild(span);
  }
  return container;
}

export function createNoData(message = 'No data available.') {
  const div = document.createElement('div');
  div.className = 'text-muted text-center py-5';
  div.textContent = message;
  return div;
}

export function createErrorCard(message = 'Something went wrong', onRetry, retryText = 'Retry') {
  const card = document.createElement('div');
  card.className = 'card border-danger';
  const body = document.createElement('div');
  body.className = 'card-body text-center';
  const p = document.createElement('p');
  p.className = 'mb-3';
  p.textContent = message;
  const btn = document.createElement('button');
  btn.type = 'button';
  btn.className = 'btn btn-outline-danger';
  btn.textContent = retryText;
  if (typeof onRetry === 'function') {
    btn.addEventListener('click', onRetry);
  }
  body.appendChild(p);
  body.appendChild(btn);
  card.appendChild(body);
  return card;
}

export default { createSkeleton, createNoData, createErrorCard };
