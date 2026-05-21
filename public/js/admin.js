function importUsers(input) {
  const file = input.files[0];
  if (!file) return;
  const formData = new FormData();
  formData.append('file', file);
  const csrfToken = document.querySelector('meta[name="csrf-token"]').content;
  fetch('/admin/import', {
    method: 'POST',
    headers: { 'x-csrf-token': csrfToken },
    body: formData
  })
    .then(r => r.text())
    .then(html => { document.open(); document.write(html); document.close(); })
    .catch(e => alert('Import failed: ' + e));
}
