export function attachValidation(input, validator) {
  const errorId = `${input.id || input.name}-error`;
  let errorEl = null;

  function showError(message) {
    if (!errorEl) {
      errorEl = document.createElement('div');
      errorEl.id = errorId;
      errorEl.className = 'invalid-feedback';
      input.parentNode.appendChild(errorEl);
    }
    errorEl.textContent = message;
    input.classList.add('is-invalid');
  }

  function clearError() {
    if (errorEl) {
      errorEl.textContent = '';
    }
    input.classList.remove('is-invalid');
  }

  input.addEventListener('input', () => {
    const message = validator(input.value);
    if (message) {
      showError(message);
    } else {
      clearError();
    }
  });

  return {
    validate() {
      const message = validator(input.value);
      if (message) {
        showError(message);
        return false;
      }
      clearError();
      return true;
    }
  };
}

export default { attachValidation };
