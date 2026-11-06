// Browser-only conveniences. Forms, validation, rendering and streams are Rust.
try {
  document.documentElement.dataset.theme = localStorage.getItem('theme') === 'light' ? 'light' : 'dark';
} catch (_) { document.documentElement.dataset.theme = 'dark'; }

function syncThemeControls() {
  const target = document.documentElement.dataset.theme === 'light' ? 'dark' : 'light';
  for (const control of document.querySelectorAll('[data-theme-toggle]')) {
    const label = `Switch to ${target} theme`;
    control.title = label;
    control.setAttribute('aria-label', label);
    const text = control.querySelector('span');
    if (text) text.textContent = target === 'light' ? 'Light mode' : 'Dark mode';
    else control.textContent = target === 'light' ? 'Light mode' : 'Dark mode';
  }
}
document.addEventListener('DOMContentLoaded', syncThemeControls);

document.addEventListener('click', async event => {
  const button = event.target.closest('[data-theme-toggle], [data-copy], [data-add-domain]');
  if (!button) return;
  if (button.hasAttribute('data-theme-toggle')) {
    const theme = document.documentElement.dataset.theme === 'light' ? 'dark' : 'light';
    document.documentElement.dataset.theme = theme;
    try { localStorage.setItem('theme', theme); } catch (_) {}
    syncThemeControls();
  } else if (button.hasAttribute('data-add-domain')) {
    const field = document.querySelector('#custom-app-form [name="wildcards"]');
    if (field) {
      const values = field.value.split(',').map(value => value.trim()).filter(Boolean);
      if (!values.includes(button.dataset.addDomain)) field.value = [...values, button.dataset.addDomain].join(', ');
      field.focus();
    }
  } else {
    try {
      await navigator.clipboard.writeText(button.dataset.copy);
      button.title = 'Copied';
    } catch (_) { button.title = 'Copy unavailable — select the text to copy'; }
  }
});
document.addEventListener('datastar-fetch', event => {
  if (!['error', 'retries-failed'].includes(event.detail?.type)) return;
  const message = document.getElementById('ui-error');
  if (message) {
    message.hidden = false;
    message.textContent = 'The request could not be completed. Your unsaved form input is still here. Retry the action or reload the page.';
  }
});
