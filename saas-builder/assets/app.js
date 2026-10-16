// Small progressive enhancements. Behaviour is declared with data-* attributes so the
// Content-Security-Policy can forbid inline scripts.
document.addEventListener('DOMContentLoaded', () => {
  // <form data-loading="Scanning…">: disable the button and show a spinner on submit
  document.querySelectorAll('form[data-loading]').forEach(form => {
    form.addEventListener('submit', () => {
      const btn = form.querySelector('button');
      if (!btn) return;
      btn.disabled = true;
      btn.innerHTML = '<span class="spinner"></span> ' + form.dataset.loading;
    });
  });

  // <form data-confirm="Are you sure?">
  document.querySelectorAll('form[data-confirm]').forEach(form => {
    form.addEventListener('submit', e => { if (!confirm(form.dataset.confirm)) e.preventDefault(); });
  });

  // <button data-copy="#selector">
  document.querySelectorAll('[data-copy]').forEach(btn => {
    btn.addEventListener('click', async () => {
      const el = document.querySelector(btn.dataset.copy);
      try {
        await navigator.clipboard.writeText(el.innerText);
        btn.innerText = 'Copied';
      } catch (e) {
        // Clipboard permission denied: select the text so the user can copy it themselves.
        const range = document.createRange();
        range.selectNodeContents(el);
        const sel = window.getSelection();
        sel.removeAllRanges();
        sel.addRange(range);
        btn.innerText = 'Press Ctrl+C';
      }
    });
  });

  document.querySelectorAll('[data-print]').forEach(btn => btn.addEventListener('click', () => window.print()));

  // <body data-reload-after="5000">
  const reloadAfter = document.body.dataset.reloadAfter;
  if (reloadAfter) setTimeout(() => location.reload(), Number(reloadAfter));

  // <body data-poll="/api/domains/1/status">: reload once the running scan finishes
  const pollUrl = document.body.dataset.poll;
  if (pollUrl) {
    const timer = setInterval(async () => {
      try {
        const s = await (await fetch(pollUrl, { credentials: 'same-origin' })).json();
        if (!s.running) { clearInterval(timer); location.reload(); }
      } catch (e) {}
    }, 3000);
  }
});
