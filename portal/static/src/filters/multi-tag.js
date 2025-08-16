export default function initMultiTagFilter(select) {
  select.style.display = 'none';
  const container = document.createElement('div');
  container.className = 'form-control d-flex flex-wrap';
  const input = document.createElement('input');
  input.type = 'text';
  input.className = 'border-0 flex-grow-1';
  input.placeholder = select.getAttribute('placeholder') || '';
  container.appendChild(input);
  select.parentNode.insertBefore(container, select);

  function render() {
    container.querySelectorAll('.tag').forEach(t => t.remove());
    Array.from(select.selectedOptions).forEach(opt => {
      const span = document.createElement('span');
      span.className = 'badge bg-primary me-1 mb-1 tag';
      span.textContent = opt.textContent;
      span.style.cursor = 'pointer';
      span.addEventListener('click', () => {
        opt.selected = false;
        render();
        select.dispatchEvent(new Event('change', { bubbles: true }));
      });
      container.insertBefore(span, input);
    });
  }

  function addTag(value) {
    value = value.trim();
    if (!value) return;
    let opt = Array.from(select.options).find(o => o.value === value);
    if (!opt) {
      opt = new Option(value, value, true, true);
      select.add(opt);
    } else {
      opt.selected = true;
    }
    render();
    select.dispatchEvent(new Event('change', { bubbles: true }));
  }

  input.addEventListener('keydown', e => {
    if (e.key === 'Enter') {
      e.preventDefault();
      addTag(input.value);
      input.value = '';
    }
  });

  render();

  return {
    getValues() {
      return Array.from(select.selectedOptions).map(o => ({
        label: select.dataset.label || select.name,
        value: o.textContent,
        name: select.name
      }));
    },
    clear() {
      Array.from(select.options).forEach(o => (o.selected = false));
      render();
    },
    clearValue(val) {
      Array.from(select.options).forEach(o => {
        if (o.value === val) o.selected = false;
      });
      render();
    }
  };
}
