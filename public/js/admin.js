function importUsers(input) {
  const file = input.files[0];
  if (!file) return;
  const formData = new FormData();
  formData.append('file', file);
  const csrfMeta = document.querySelector('meta[name="csrf-token"]');
  const csrfToken = csrfMeta ? csrfMeta.getAttribute('content') : '';
  fetch('/admin/import', {
    method: 'POST',
    headers: { 'x-csrf-token': csrfToken },
    body: formData
  })
    .then(r => r.text())
    .then(html => {
      document.open();
      document.write(html);
      document.close();
    })
    .catch(() => alert('Import failed'));
}
