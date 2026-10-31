/* SecureNotes: the UI.
   XSS RULE: user text is only ever put on the page with textContent (never innerHTML),
   so "<script>" or "<img onerror=...>" is shown as plain characters and never runs. */
(function () {
  'use strict';
  const V = window.Validate;
  const Api = window.Api;
  const $ = (id) => document.getElementById(id);

  const state = { user: null, notes: [], q: '', mode: 'login', editingId: null, deleting: null };

  function el(tag, cls, text, parent) {
    const e = document.createElement(tag);
    if (cls) e.className = cls;
    if (text !== undefined && text !== null) e.textContent = text;   // textContent: always plain text
    if (parent) parent.appendChild(e);
    return e;
  }
  const fmtDate = (ms) => new Intl.DateTimeFormat('en-GB', { day: 'numeric', month: 'short', year: 'numeric', hour: '2-digit', minute: '2-digit' }).format(new Date(ms));

  /* ---------- toasts ---------- */
  function toast(msg, type) {
    const box = $('toasts');
    const t = el('div', 'toast ' + (type || 'info'), msg, box);
    t.setAttribute('role', type === 'error' ? 'alert' : 'status');
    setTimeout(() => { t.classList.add('out'); setTimeout(() => t.remove(), 250); }, type === 'error' ? 6000 : 3500);
  }

  /* ---------- views ---------- */
  function show(view) {
    $('boot').hidden = true;
    $('view-auth').hidden = view !== 'auth';
    $('view-notes').hidden = view !== 'notes';
    const on = view === 'notes';
    $('who').hidden = !on; $('logout').hidden = !on;
    if (on) $('who').textContent = state.user.name;
    document.title = (on ? 'Your notes' : 'Log in') + ' - SecureNotes';
  }

  function enterApp(user, csrf) {
    state.user = user; Api.setCsrf(csrf);
    state.q = ''; $('search').value = '';
    show('notes');
    loadNotes(true);
  }
  function leaveApp(message, type) {
    state.user = null; state.notes = []; Api.setCsrf(null);
    $('grid').replaceChildren();
    show('auth'); setMode('login');
    if (message) toast(message, type || 'info');
    $('email').focus();
  }

  /* ---------- field errors ---------- */
  function setErr(inputId, errId, msg) {
    const input = $(inputId), p = $(errId);
    if (!input || !p) return;
    p.hidden = !msg; p.textContent = msg || '';
    if (msg) input.setAttribute('aria-invalid', 'true'); else input.removeAttribute('aria-invalid');
  }
  function showErrors(map, errors) {
    let first = null;
    Object.keys(map).forEach((f) => {
      const msg = errors && errors[f];
      setErr(map[f][0], map[f][1], msg);
      if (msg && !first) first = $(map[f][0]);
    });
    if (first) first.focus();
  }
  const AUTH_MAP = { name: ['name', 'e-name'], email: ['email', 'e-email'], password: ['password', 'e-password'] };
  const NOTE_MAP = { title: ['n-title', 'e-title'], body: ['n-body', 'e-body'] };
  function formError(id, msg) { const p = $(id); p.hidden = !msg; p.textContent = msg || ''; }

  /* ---------- auth ---------- */
  function setMode(mode) {
    state.mode = mode;
    const signup = mode === 'signup';
    $('tab-login').setAttribute('aria-selected', String(!signup)); $('tab-login').tabIndex = signup ? -1 : 0;
    $('tab-signup').setAttribute('aria-selected', String(signup)); $('tab-signup').tabIndex = signup ? 0 : -1;
    $('auth-form').setAttribute('aria-labelledby', signup ? 'tab-signup' : 'tab-login');
    $('f-name').hidden = !signup;
    $('pw-hint').hidden = !signup;
    $('password').autocomplete = signup ? 'new-password' : 'current-password';
    $('auth-submit').textContent = signup ? 'Create account' : 'Log in';
    showErrors(AUTH_MAP, {}); formError('auth-error', '');
  }
  document.querySelectorAll('[role="tab"]').forEach((t) => {
    t.addEventListener('click', () => setMode(t.dataset.mode));
    t.addEventListener('keydown', (e) => {                       // arrow keys move between tabs
      if (e.key !== 'ArrowLeft' && e.key !== 'ArrowRight') return;
      const next = state.mode === 'login' ? 'signup' : 'login';
      setMode(next); $('tab-' + next).focus(); e.preventDefault();
    });
  });
  $('pw-toggle').addEventListener('click', () => {
    const p = $('password'), on = p.type === 'password';
    p.type = on ? 'text' : 'password';
    $('pw-toggle').textContent = on ? 'Hide' : 'Show';
    $('pw-toggle').setAttribute('aria-pressed', String(on));
  });

  $('auth-form').addEventListener('submit', async (e) => {
    e.preventDefault();
    const signup = state.mode === 'signup';
    const input = { email: $('email').value, password: $('password').value };
    if (signup) input.name = $('name').value;
    const v = signup ? V.validateSignup(input) : V.validateLogin(input);   // client-side check (the server checks again)
    formError('auth-error', '');
    showErrors(AUTH_MAP, v.errors);
    if (!v.ok) return;

    const btn = $('auth-submit');
    btn.disabled = true; btn.textContent = signup ? 'Creating account…' : 'Logging in…';
    try {
      const data = await Api.post(signup ? '/api/signup' : '/api/login', input);
      $('password').value = '';
      enterApp(data.user, data.csrfToken);
      toast(signup ? 'Welcome, ' + data.user.name + '! Your account is ready.' : 'Logged in.', 'success');
    } catch (err) {
      if (err.fields) showErrors(AUTH_MAP, err.fields);
      else formError('auth-error', err.message);
      if (err.code === 'BAD_CREDENTIALS') $('password').select();
    } finally {
      btn.disabled = false; btn.textContent = state.mode === 'signup' ? 'Create account' : 'Log in';
    }
  });

  $('logout').addEventListener('click', async () => {
    try { await Api.post('/api/logout'); leaveApp('You are logged out.', 'success'); }
    catch (err) { if (err.status === 401) leaveApp('You are logged out.', 'success'); else toast(err.message, 'error'); }
  });

  /* ---------- notes ---------- */
  function handleApiError(err, what) {
    if (err.status === 401) return leaveApp('Your session ended. Please log in again.', 'error');
    if (err.code === 'CSRF_TOKEN') { refreshSession(); }
    toast((what ? what + ' ' : '') + err.message, 'error');
  }
  async function refreshSession() {
    try { const s = await Api.get('/api/session'); if (s.user) Api.setCsrf(s.csrfToken); else leaveApp('Your session ended. Please log in again.', 'error'); } catch (e) { /* offline */ }
  }

  let loadSeq = 0;
  async function loadNotes(initial) {
    const seq = ++loadSeq;
    const q = state.q;
    $('grid').setAttribute('aria-busy', 'true');
    try {
      const data = await Api.get('/api/notes' + (q ? '?q=' + encodeURIComponent(q) : ''));
      if (seq !== loadSeq) return;                                  // an older answer arrived late: ignore it
      state.notes = data.notes;
      renderNotes();
    } catch (err) {
      if (seq !== loadSeq) return;
      if (err.status === 401) return handleApiError(err);
      if (initial) { $('grid').replaceChildren(); showEmpty('Could not load your notes', err.message, 'Try again', () => loadNotes(true)); }
      else toast(err.message, 'error');
    } finally { if (seq === loadSeq) $('grid').removeAttribute('aria-busy'); }
  }

  function showEmpty(title, text, buttonLabel, onClick) {
    $('empty').hidden = false;
    $('empty-title').textContent = title;
    $('empty-text').textContent = text;                               // the search text may be in here: textContent keeps it safe
    const b = $('empty-new');
    b.hidden = !buttonLabel;
    if (buttonLabel) { b.textContent = buttonLabel; b.onclick = onClick; }
  }

  function renderNotes() {
    const grid = $('grid');
    grid.replaceChildren();
    $('notes-sub').textContent = state.q ? state.notes.length + (state.notes.length === 1 ? ' note matches' : ' notes match') : (state.notes.length ? state.notes.length + (state.notes.length === 1 ? ' note' : ' notes') + '. Only you can see these.' : 'Only you can see these.');
    $('notes-status').textContent = state.q ? state.notes.length + ' results' : '';
    if (!state.notes.length) {
      if (state.q) showEmpty('No notes match', 'Nothing found for “' + state.q + '”. Try a different word.', '', null);
      else showEmpty('No notes yet', 'Create your first note. It is stored privately in your account.', 'Create a note', () => openEditor(null));
      return;
    }
    $('empty').hidden = true;
    state.notes.forEach((n) => {
      const card = el('article', 'note card', null, grid);
      card.setAttribute('aria-labelledby', 'nt-' + n.id);
      const h = el('h2', 'note-title', n.title, card); h.id = 'nt-' + n.id;
      if (n.body) el('p', 'note-body', n.body, card);
      const foot = el('div', 'note-foot', null, card);
      el('time', 'note-date', 'Updated ' + fmtDate(n.updatedAt), foot).setAttribute('datetime', new Date(n.updatedAt).toISOString());
      const acts = el('div', 'note-actions', null, foot);
      const edit = el('button', 'btn sm', 'Edit', acts); edit.type = 'button';
      edit.setAttribute('aria-label', 'Edit note: ' + n.title);
      edit.addEventListener('click', () => openEditor(n));
      const del = el('button', 'btn sm danger-ghost', 'Delete', acts); del.type = 'button';
      del.setAttribute('aria-label', 'Delete note: ' + n.title);
      del.addEventListener('click', () => askDelete(n, del));
    });
  }

  /* search (debounced; also validated before sending) */
  let searchTimer = null;
  function runSearch() {
    const v = V.validateSearch($('search').value);
    setErr('search', 'e-search', v.errors.q);
    if (!v.ok) return;
    state.q = v.value;
    loadNotes(false);
  }
  $('search').addEventListener('input', () => { clearTimeout(searchTimer); searchTimer = setTimeout(runSearch, 250); });
  $('search-form').addEventListener('submit', (e) => { e.preventDefault(); clearTimeout(searchTimer); runSearch(); });

  /* ---------- note editor ---------- */
  const dlg = $('note-dlg');
  let opener = null;
  const count = () => {
    $('c-title').textContent = $('n-title').value.length + ' / 100';
    $('c-body').textContent = $('n-body').value.length + ' / 5000';
  };
  function openEditor(note) {
    opener = document.activeElement;
    state.editingId = note ? note.id : null;
    $('note-dlg-title').textContent = note ? 'Edit note' : 'New note';
    $('n-title').value = note ? note.title : '';
    $('n-body').value = note ? note.body : '';
    showErrors(NOTE_MAP, {}); formError('note-error', ''); count();
    dlg.showModal();
    $('n-title').focus();
  }
  function closeEditor() { dlg.close(); if (opener && opener.focus && document.contains(opener)) opener.focus(); }
  $('new-note').addEventListener('click', () => openEditor(null));
  $('note-cancel').addEventListener('click', closeEditor);
  $('n-title').addEventListener('input', count);
  $('n-body').addEventListener('input', count);

  $('note-form').addEventListener('submit', async (e) => {
    e.preventDefault();
    const input = { title: $('n-title').value, body: $('n-body').value };
    const v = V.validateNote(input);
    formError('note-error', '');
    showErrors(NOTE_MAP, v.errors);
    if (!v.ok) return;
    const btn = $('note-save');
    btn.disabled = true; btn.textContent = 'Saving…';
    try {
      if (state.editingId) await Api.put('/api/notes/' + state.editingId, input);
      else await Api.post('/api/notes', input);
      closeEditor();
      toast(state.editingId ? 'Note updated.' : 'Note saved.', 'success');
      await loadNotes(false);
    } catch (err) {
      if (err.fields) showErrors(NOTE_MAP, err.fields);
      else if (err.status === 401) { closeEditor(); handleApiError(err); }
      else { formError('note-error', err.message); if (err.code === 'CSRF_TOKEN') refreshSession(); }
    } finally { btn.disabled = false; btn.textContent = 'Save note'; }
  });

  /* ---------- delete ---------- */
  const cdlg = $('confirm-dlg');
  function askDelete(note, opener2) {
    state.deleting = { note, opener: opener2 };
    $('confirm-text').textContent = '“' + note.title + '” will be removed for good.';
    cdlg.showModal();
    $('confirm-cancel').focus();
  }
  $('confirm-cancel').addEventListener('click', () => cdlg.close());
  $('confirm-form').addEventListener('submit', async (e) => {
    e.preventDefault();
    const d = state.deleting; if (!d) return;
    const btn = $('confirm-ok'); btn.disabled = true; btn.textContent = 'Deleting…';
    try {
      await Api.del('/api/notes/' + d.note.id);
      cdlg.close(); toast('Note deleted.', 'success');
      await loadNotes(false);
      $('new-note').focus();
    } catch (err) {
      cdlg.close();
      if (err.status === 404) { toast('That note was already deleted.', 'info'); loadNotes(false); }
      else handleApiError(err, 'Could not delete the note.');
    } finally { btn.disabled = false; btn.textContent = 'Delete'; state.deleting = null; }
  });

  /* ---------- theme ---------- */
  function syncTheme() {
    const dark = document.documentElement.getAttribute('data-theme') === 'dark';
    $('theme').setAttribute('aria-label', dark ? 'Switch to light theme' : 'Switch to dark theme');
  }
  $('theme').addEventListener('click', () => {
    const next = document.documentElement.getAttribute('data-theme') === 'dark' ? 'light' : 'dark';
    document.documentElement.setAttribute('data-theme', next);
    try { localStorage.setItem('securenotes-theme', next); } catch (e) { /* ignore */ }
    syncTheme();
  });

  /* ---------- start ---------- */
  async function boot() {
    syncTheme();
    try {
      const s = await Api.get('/api/session');
      if (s.user) enterApp(s.user, s.csrfToken);
      else { show('auth'); setMode('login'); }
    } catch (err) {
      $('boot').textContent = err.message;
      const retry = el('button', 'btn', 'Try again', $('boot').parentNode);
      retry.type = 'button'; retry.addEventListener('click', () => { retry.remove(); $('boot').textContent = 'Loading…'; boot(); });
    }
  }
  boot();
})();
