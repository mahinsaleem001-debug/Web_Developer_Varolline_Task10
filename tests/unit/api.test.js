const test = require('node:test');
const assert = require('node:assert/strict');
const { startApp } = require('./helpers');

let ctx;
test.before(async () => { ctx = await startApp({ loginMax: 4, signupMax: 1000 }); });
test.after(async () => { await ctx.stop(); });

/* ---------- authentication ---------- */
test('signup creates an account, starts a session and sets a safe cookie', async () => {
  const c = ctx.client();
  const r = await c.signup('signup1@example.com');
  assert.equal(r.status, 201);
  assert.equal(r.body.user.email, 'signup1@example.com');
  assert.ok(r.body.csrfToken);
  assert.equal(r.body.user.password_hash, undefined, 'the hash is never sent to the browser');
  const cookie = r.setCookie.find((x) => x.startsWith('sid='));
  assert.match(cookie, /HttpOnly/i); assert.match(cookie, /SameSite=Strict/i); assert.match(cookie, /Path=\//);
  assert.equal((await c.call('GET', '/api/session')).body.user.email, 'signup1@example.com');
});
test('signup: server-side validation rejects bad input even if the browser check is skipped', async () => {
  const c = ctx.client();
  const r = await c.signup('not-an-email', '<script>x</script>', 'weak');
  assert.equal(r.status, 400); assert.equal(r.body.error.code, 'VALIDATION');
  assert.ok(r.body.error.fields.email && r.body.error.fields.name && r.body.error.fields.password);
});
test('signup: duplicate email is refused (case-insensitive)', async () => {
  await ctx.client().signup('dup@example.com');
  const r = await ctx.client().signup('DUP@example.com');
  assert.equal(r.status, 409); assert.equal(r.body.error.code, 'EMAIL_TAKEN');
});
test('passwords are stored as bcrypt hashes, never as text', async () => {
  await ctx.client().signup('hash@example.com', 'Hash Test', 'correct horse 9');
  const row = ctx.store.raw.prepare('SELECT password_hash FROM users WHERE email = ?').get('hash@example.com');
  assert.match(row.password_hash, /^\$2[aby]\$\d\d\$/); assert.ok(!row.password_hash.includes('correct horse'));
});
test('session cookie value is not stored: only its SHA-256 hash is in the database', async () => {
  const c = ctx.client(); await c.signup('tok@example.com');
  const token = c.cookie.split('=')[1];
  assert.equal(ctx.store.raw.prepare('SELECT COUNT(*) n FROM sessions WHERE id = ?').get(token).n, 0);
  assert.equal(ctx.store.raw.prepare('SELECT COUNT(*) n FROM sessions WHERE id = ?').get(require('../../server/security').sha256(token)).n, 1);
});
test('login: right password works, wrong password and unknown email give the SAME message', async () => {
  await ctx.client().signup('login1@example.com');
  assert.equal((await ctx.client().login('login1@example.com')).status, 200);
  const bad = await ctx.client().login('login1@example.com', 'wrong password 1');
  const ghost = await ctx.client().login('nobody@example.com', 'wrong password 1');
  assert.equal(bad.status, 401); assert.equal(ghost.status, 401);
  assert.equal(bad.body.error.message, ghost.body.error.message, 'no hint about which emails exist');
});
test('login: SQL injection strings do not log anyone in', async () => {
  await ctx.client().signup('sqli@example.com');
  for (const email of ["' OR '1'='1", "sqli@example.com' --", "' OR 1=1 --@x.co"]) assert.ok([400, 401].includes((await ctx.client().login(email, 'x')).status), email);
  for (const pw of ["' OR '1'='1", "x' OR '1'='1' --", '" OR ""="']) assert.equal((await ctx.client().login('sqli@example.com', pw)).status, 401, pw);
});
test('login: after too many failures the account is rate limited (429 + Retry-After)', async () => {
  await ctx.client().signup('rate@example.com');
  const c = ctx.client();
  for (let i = 0; i < 4; i++) assert.equal((await c.login('rate@example.com', 'wrong password ' + i)).status, 401);
  const r = await c.login('rate@example.com', 'wrong password x');
  assert.equal(r.status, 429); assert.ok(Number(r.headers.get('retry-after')) > 0);
  assert.equal((await c.login('rate@example.com')).status, 429, 'even the right password waits');
});
test('login: a fresh session replaces the old one (no session fixation)', async () => {
  const c = ctx.client(); await c.signup('fix@example.com');
  const before = c.cookie; await c.login('fix@example.com');
  assert.notEqual(c.cookie, before);
  const old = ctx.client(); old.cookie = before;
  assert.equal((await old.call('GET', '/api/session')).body.user, null);
});
test('logout ends the session on the server', async () => {
  const c = ctx.client(); await c.signup('out@example.com');
  const stolen = c.cookie;
  assert.equal((await c.call('POST', '/api/logout', {})).status, 200);
  const thief = ctx.client(); thief.cookie = stolen; thief.csrf = c.csrf;
  assert.equal((await thief.call('GET', '/api/notes')).status, 401, 'the old cookie is dead');
});
test('expired sessions stop working', async () => {
  let t = 1_000_000;
  const short = await startApp({ sessionTtlMs: 1000, now: () => t });
  try {
    const c = short.client(); await c.signup('exp@example.com');
    assert.equal((await c.call('GET', '/api/notes')).status, 200);
    t += 2000;
    assert.equal((await c.call('GET', '/api/notes')).status, 401);
  } finally { await short.stop(); }
});

/* ---------- CSRF ---------- */
test('CSRF: a request without the X-Requested-With header is blocked', async () => {
  const c = ctx.client(); await c.signup('csrf1@example.com');
  const r = await c.call('POST', '/api/notes', { title: 'x' }, { plain: true });
  assert.equal(r.status, 403); assert.equal(r.body.error.code, 'CSRF_HEADER');
});
test('CSRF: logged in but without the secret token is blocked', async () => {
  const c = ctx.client(); await c.signup('csrf2@example.com');
  const r = await c.call('POST', '/api/notes', { title: 'x' }, { noCsrf: true });
  assert.equal(r.status, 403); assert.equal(r.body.error.code, 'CSRF_TOKEN');
});
test('CSRF: a wrong token is blocked, the right one works', async () => {
  const c = ctx.client(); await c.signup('csrf3@example.com');
  const good = c.csrf;
  c.csrf = 'A'.repeat(good.length);
  assert.equal((await c.call('POST', '/api/notes', { title: 'x' })).body.error.code, 'CSRF_TOKEN');
  c.csrf = good;
  assert.equal((await c.call('POST', '/api/notes', { title: 'x' })).status, 201);
});
test('CSRF: a token from another user\'s session does not work', async () => {
  const a = ctx.client(); await a.signup('csrf4a@example.com');
  const b = ctx.client(); await b.signup('csrf4b@example.com');
  b.csrf = a.csrf;
  assert.equal((await b.call('POST', '/api/notes', { title: 'x' })).status, 403);
});
test('CSRF: a request from another origin is blocked, even with every token', async () => {
  const c = ctx.client(); await c.signup('csrf5@example.com');
  for (const origin of ['http://evil.test', 'null', 'http://127.0.0.1.evil.test']) {
    const r = await c.call('POST', '/api/notes', { title: 'x' }, { headers: { Origin: origin } });
    assert.equal(r.status, 403, origin); assert.equal(r.body.error.code, 'CSRF_ORIGIN');
  }
  assert.equal((await c.call('POST', '/api/notes', { title: 'ok' }, { headers: { Origin: c.base } })).status, 201);
});
test('CSRF: an HTML form post (form content-type) is refused', async () => {
  const c = ctx.client(); await c.signup('csrf6@example.com');
  const r = await c.call('POST', '/api/notes', 'title=x', { headers: { 'Content-Type': 'application/x-www-form-urlencoded' } });
  assert.equal(r.status, 415);
});
test('CSRF: login and signup need the header too (login CSRF)', async () => {
  const r = await ctx.client().call('POST', '/api/login', { email: 'a@b.co', password: 'x' }, { plain: true });
  assert.equal(r.status, 403);
});
test('the server sends no CORS headers, so other sites cannot read responses', async () => {
  const r = await ctx.client().call('GET', '/api/session', undefined, { headers: { Origin: 'http://evil.test' } });
  assert.equal(r.headers.get('access-control-allow-origin'), null);
});

/* ---------- notes: access control ---------- */
test('notes need a login', async () => {
  const c = ctx.client();
  assert.equal((await c.call('GET', '/api/notes')).status, 401);
  assert.equal((await c.call('POST', '/api/notes', { title: 'x' })).status, 401);
});
test('notes: create, list, edit, delete', async () => {
  const c = ctx.client(); await c.signup('notes1@example.com');
  const n = (await c.call('POST', '/api/notes', { title: '  First  note ', body: 'Hello' })).body.note;
  assert.equal(n.title, 'First note');
  assert.equal((await c.call('GET', '/api/notes')).body.notes.length, 1);
  assert.equal((await c.call('PUT', '/api/notes/' + n.id, { title: 'Renamed', body: 'Bye' })).body.note.title, 'Renamed');
  assert.equal((await c.call('DELETE', '/api/notes/' + n.id)).status, 200);
  assert.equal((await c.call('GET', '/api/notes')).body.notes.length, 0);
});
test('access control: users cannot read, edit or delete each other\'s notes (IDOR)', async () => {
  const a = ctx.client(); await a.signup('idor-a@example.com');
  const b = ctx.client(); await b.signup('idor-b@example.com');
  const note = (await a.call('POST', '/api/notes', { title: 'A secret', body: 'private' })).body.note;
  assert.equal((await b.call('GET', '/api/notes')).body.notes.length, 0);
  assert.equal((await b.call('PUT', '/api/notes/' + note.id, { title: 'Hacked' })).status, 404);
  assert.equal((await b.call('DELETE', '/api/notes/' + note.id)).status, 404);
  assert.equal((await b.call('GET', '/api/notes?q=secret')).body.notes.length, 0);
  assert.equal((await a.call('GET', '/api/notes')).body.notes[0].title, 'A secret', 'untouched');
});
test('notes: bad ids and bodies are rejected', async () => {
  const c = ctx.client(); await c.signup('notes2@example.com');
  for (const id of ['abc', '0', '-1', '1 OR 1=1', '9'.repeat(30)]) assert.equal((await c.call('DELETE', '/api/notes/' + encodeURIComponent(id))).status, 404, id);
  assert.equal((await c.call('POST', '/api/notes', { title: '' })).status, 400);
  assert.equal((await c.call('POST', '/api/notes', { title: { $ne: 1 } })).status, 400);
  assert.equal((await c.call('POST', '/api/notes', '{bad json')).status, 400);
  assert.equal((await c.call('POST', '/api/notes', { title: 'x', body: 'y'.repeat(30000) })).status, 413, 'oversized body');
});
test('XSS: HTML in a note is stored as plain text and returned as JSON (never as HTML)', async () => {
  const c = ctx.client(); await c.signup('xss@example.com');
  const payload = '<img src=x onerror=alert(1)><script>alert(2)</script>';
  const r = await c.call('POST', '/api/notes', { title: payload, body: payload });
  assert.equal(r.status, 201); assert.equal(r.body.note.title, payload);
  const list = await c.call('GET', '/api/notes');
  assert.match(list.headers.get('content-type'), /application\/json/);
  assert.equal(list.headers.get('x-content-type-options'), 'nosniff');
});
test('search: SQL injection and wildcard strings are harmless', async () => {
  const c = ctx.client(); await c.signup('search@example.com');
  await c.call('POST', '/api/notes', { title: 'Milk', body: 'buy 100% juice' });
  await c.call('POST', '/api/notes', { title: 'Other', body: 'x' });
  const q = async (s) => (await c.call('GET', '/api/notes?q=' + encodeURIComponent(s))).body.notes.length;
  assert.equal(await q("' OR '1'='1"), 0);
  assert.equal(await q("%' OR 1=1 --"), 0);
  assert.equal(await q('milk'), 1);
  assert.equal(await q('%'), 1, '% is a literal character');
  assert.equal((await c.call('GET', '/api/notes?q=' + 'x'.repeat(60))).status, 400);
  assert.equal((await c.call('GET', '/api/notes?q[]=a&q[]=b')).status, 400);
  assert.equal((await c.call('GET', '/api/notes')).body.notes.length, 2, 'nothing was dropped');
});

/* ---------- headers and errors ---------- */
test('security headers are on every response', async () => {
  const r = await ctx.client().call('GET', '/api/session');
  const csp = r.headers.get('content-security-policy');
  assert.match(csp, /default-src 'none'/); assert.match(csp, /script-src 'self'/); assert.match(csp, /frame-ancestors 'none'/);
  assert.match(csp, /object-src 'none'/); assert.match(csp, /base-uri 'none'/); assert.match(csp, /form-action 'self'/);
  assert.ok(!/unsafe-inline|unsafe-eval/.test(csp), 'no unsafe-inline / unsafe-eval');
  assert.equal(r.headers.get('x-content-type-options'), 'nosniff');
  assert.equal(r.headers.get('x-frame-options'), 'DENY');
  assert.equal(r.headers.get('referrer-policy'), 'no-referrer');
  assert.match(r.headers.get('permissions-policy'), /camera=\(\)/);
  assert.equal(r.headers.get('cross-origin-opener-policy'), 'same-origin');
  assert.equal(r.headers.get('cache-control'), 'no-store');
  assert.equal(r.headers.get('x-powered-by'), null, 'does not announce Express');
});
test('the web page itself carries the same security headers', async () => {
  const res = await fetch(ctx.base + '/');
  assert.equal(res.status, 200);
  assert.match(res.headers.get('content-security-policy'), /script-src 'self'/);
  const html = await res.text();
  assert.ok(!/<script(?![^>]*\bsrc=)/i.test(html), 'no inline <script> in the page');
  assert.ok(!/\sstyle=/i.test(html) && !/\son\w+=/i.test(html), 'no inline style or event handler attributes');
});
test('production mode adds HSTS, upgrade-insecure-requests and the Secure cookie flag', async () => {
  const prod = await startApp({ production: true });
  try {
    const c = prod.client(); const r = await c.signup('prod@example.com');
    assert.match(r.headers.get('strict-transport-security'), /max-age=31536000/);
    assert.match(r.headers.get('content-security-policy'), /upgrade-insecure-requests/);
    assert.match(r.setCookie.find((x) => x.startsWith('sid=')), /Secure/i);
  } finally { await prod.stop(); }
});
test('errors do not leak internals', async () => {
  const c = ctx.client();
  const r = await c.call('POST', '/api/login', '{"email":', { headers: { 'Content-Type': 'application/json' } });
  assert.equal(r.status, 400); assert.ok(!JSON.stringify(r.body).match(/SyntaxError|at .*\.js|node_modules/));
  const nf = await c.call('GET', '/api/does-not-exist');
  assert.equal(nf.status, 404); assert.equal(nf.body.error.code, 'NOT_FOUND');
});
test('hidden files and the database are not served', async () => {
  for (const p of ['/.env', '/../package.json', '/server/app.js', '/data/securenotes.db', '/%2e%2e/package.json']) {
    const res = await fetch(ctx.base + p); assert.notEqual(res.status, 200, p);
  }
});

test('signup is rate limited per address', async () => {
  const lim = await startApp({ signupMax: 3 });
  try {
    for (let i = 0; i < 3; i++) assert.equal((await lim.client().signup('lim' + i + '@example.com')).status, 201);
    const r = await lim.client().signup('lim9@example.com');
    assert.equal(r.status, 429); assert.ok(r.headers.get('retry-after'));
  } finally { await lim.stop(); }
});
