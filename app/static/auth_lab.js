// Synthetic local training requests only. No passwords or real user data are sent.
async function attempt(path, inputId, resultId, btnId) {
  const button = document.getElementById(btnId);
  const status = document.getElementById(resultId);
  const password = document.getElementById(inputId).value;
  button.disabled = true;
  try {
    const res = await fetch(path, {
      method: 'POST',
      headers: {'Content-Type': 'application/x-www-form-urlencoded'},
      body: new URLSearchParams({password})
    });
    const data = await res.json();
    status.textContent = `HTTP ${res.status} — ${data.message || data.error || data.status} (attempts: ${data.attempts ?? '?'})`;
  } catch (err) {
    status.textContent = 'Request failed: is your Flask server still running?';
  } finally {
    button.disabled = false;
  }
}
document.getElementById('weak-btn').addEventListener('click', () => attempt('/lab/auth/vulnerable/attempt','weak-pass','weak-result','weak-btn'));
document.getElementById('safe-btn').addEventListener('click', () => attempt('/lab/auth/safe/attempt','safe-pass','safe-result','safe-btn'));
document.getElementById('reset-btn').addEventListener('click', async () => {
  try {
    const res = await fetch('/lab/auth/reset', {method:'POST'});
    if (!res.ok) throw new Error();
    document.getElementById('weak-result').textContent='Counters reset';
    document.getElementById('safe-result').textContent='Counters reset';
  } catch (_) { alert('Reset failed. Check your Flask server.'); }
});
