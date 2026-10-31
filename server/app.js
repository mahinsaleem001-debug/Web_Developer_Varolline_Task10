/* SecureNotes: the Express app. createApp() is a function so tests can start a fresh app with its own database. */
const path = require('path');
const express = require('express');
const helmet = require('helmet');
const bcrypt = require('bcryptjs');
const { openDb, MAX_NOTES_PER_USER } = require('./db');
const sec = require('./security');
const V = require('../public/js/validate.js');

const SESSION_COOKIE = 'sid';
const DAY = 24 * 60 * 60 * 1000;

class HttpError extends Error {
  constructor(status, code, message, fields) { super(message); this.status = status; this.code = code; this.fields = fields; }
}

function createApp(options = {}) {
  const o = Object.assign({
    dbFile: ':memory:', bcryptCost: 12, production: false, trustProxy: false,
    sessionTtlMs: DAY, loginMax: 8, loginWindowMs: 15 * 60 * 1000, signupMax: 10, signupWindowMs: 60 * 60 * 1000,
    now: () => Date.now(), quiet: false
  }, options);

  const store = openDb(o.dbFile);
  const app = express();
  app.disable('x-powered-by');                       // do not advertise the framework
  if (o.trustProxy) app.set('trust proxy', 1);

  /* ---------- 1. Secure headers ---------- */
  app.use(helmet({
    contentSecurityPolicy: {
      useDefaults: false,
      directives: {
        'default-src': ["'none'"],
        'script-src': ["'self'"],                    // no inline scripts, so injected <script> cannot run
        'style-src': ["'self'"],
        'img-src': ["'self'", 'data:'],
        'connect-src': ["'self'"],
        'font-src': ["'self'"],
        'manifest-src': ["'self'"],
        'object-src': ["'none'"],
        'base-uri': ["'none'"],
        'form-action': ["'self'"],
        'frame-ancestors': ["'none'"],               // nobody can put this site in an iframe (clickjacking)
        ...(o.production ? { 'upgrade-insecure-requests': [] } : {})
      }
    },
    frameguard: { action: 'deny' },
    referrerPolicy: { policy: 'no-referrer' },
    hsts: o.production ? { maxAge: 31536000, includeSubDomains: true } : false,
    crossOriginResourcePolicy: { policy: 'same-origin' },
    crossOriginOpenerPolicy: { policy: 'same-origin' }
  }));
  app.use((req, res, next) => {
    res.setHeader('Permissions-Policy', 'camera=(), microphone=(), geolocation=(), payment=(), usb=()');
    res.setHeader('X-Permitted-Cross-Domain-Policies', 'none');
    if (req.path.startsWith('/api/')) { res.setHeader('Cache-Control', 'no-store'); res.setHeader('Pragma', 'no-cache'); }
    next();
  });

  app.use(express.json({ limit: '20kb', strict: true }));   // small body limit stops huge payloads

  /* ---------- 2. CSRF + request hygiene for every state-changing request ---------- */
  app.use('/api', (req, res, next) => {
    if (['GET', 'HEAD', 'OPTIONS'].includes(req.method)) return next();
    if (!sec.originAllowed(req)) return next(new HttpError(403, 'CSRF_ORIGIN', 'Request blocked: it did not come from this site.'));
    // A cross-site page cannot add this header without a CORS preflight, which this server never approves.
    if (req.headers['x-requested-with'] !== 'securenotes') return next(new HttpError(403, 'CSRF_HEADER', 'Request blocked: missing security header.'));
    if (req.is('application/json') === false) return next(new HttpError(415, 'UNSUPPORTED_MEDIA_TYPE', 'Send JSON (Content-Type: application/json).'));
    next();
  });

  /* ---------- 3. Sessions (server side, revocable) ---------- */
  const loginLimiter = sec.createLimiter({ windowMs: o.loginWindowMs, max: o.loginMax, now: o.now });
  const signupLimiter = sec.createLimiter({ windowMs: o.signupWindowMs, max: o.signupMax, now: o.now });
  const DUMMY_HASH = bcrypt.hashSync('not-a-real-password', o.bcryptCost);  // used so unknown emails take as long as real ones

  function cookieOptions(maxAgeMs) {
    return { httpOnly: true, sameSite: 'strict', secure: o.production, path: '/', maxAge: maxAgeMs };
  }
  function startSession(res, userId) {
    const token = sec.newToken();
    const csrf = sec.newToken(24);
    const t = o.now();
    store.deleteExpiredSessions(t);
    store.createSession(sec.sha256(token), userId, csrf, t, t + o.sessionTtlMs);
    res.cookie(SESSION_COOKIE, token, cookieOptions(o.sessionTtlMs));
    return csrf;
  }
  function currentSession(req) {
    const token = sec.parseCookies(req.headers.cookie)[SESSION_COOKIE];
    if (!token || token.length > 128) return null;
    const row = store.findSession(sec.sha256(token));
    if (!row) return null;
    if (row.expires_at <= o.now()) { store.deleteSession(row.id); return null; }
    return row;
  }
  const publicUser = (u) => ({ id: u.id, name: u.name, email: u.email });

  function requireAuth(req, res, next) {
    const s = currentSession(req);
    if (!s) return next(new HttpError(401, 'UNAUTHENTICATED', 'Please log in.'));
    req.session = s;
    if (!['GET', 'HEAD'].includes(req.method) && !sec.safeEqual(req.headers['x-csrf-token'], s.csrf_token)) {
      return next(new HttpError(403, 'CSRF_TOKEN', 'Request blocked: invalid security token. Refresh the page and try again.'));
    }
    next();
  }

  const fail = (v) => { throw new HttpError(400, 'VALIDATION', 'Please fix the highlighted fields.', v.errors); };
  const clientIp = (req) => req.ip || (req.socket && req.socket.remoteAddress) || 'unknown';

  /* ---------- 4. Auth routes ---------- */
  app.get('/api/session', (req, res) => {
    const s = currentSession(req);
    if (!s) return res.json({ user: null, csrfToken: null });
    res.json({ user: { id: s.user_id, name: s.name, email: s.email }, csrfToken: s.csrf_token });
  });

  app.post('/api/signup', async (req, res, next) => {
    try {
      const gate = signupLimiter.hit(clientIp(req));
      if (!gate.allowed) { res.set('Retry-After', String(gate.retryAfterSec)); throw new HttpError(429, 'RATE_LIMITED', 'Too many sign-ups from this address. Try again later.'); }
      const v = V.validateSignup(req.body);
      if (!v.ok) fail(v);
      if (store.findUserByEmail(v.value.email)) throw new HttpError(409, 'EMAIL_TAKEN', 'An account with this email already exists.', { email: 'An account with this email already exists.' });
      const hash = await bcrypt.hash(v.value.password, o.bcryptCost);   // salted, slow hash: stolen databases are hard to crack
      let id;
      try { id = store.createUser(v.value.email, v.value.name, hash, o.now()); }
      catch (e) { if (/constraint failed/i.test(String(e && e.message))) throw new HttpError(409, 'EMAIL_TAKEN', 'An account with this email already exists.', { email: 'An account with this email already exists.' }); throw e; }
      const csrfToken = startSession(res, id);
      res.status(201).json({ user: { id, name: v.value.name, email: v.value.email }, csrfToken });
    } catch (e) { next(e); }
  });

  app.post('/api/login', async (req, res, next) => {
    try {
      const v = V.validateLogin(req.body);
      if (!v.ok) fail(v);
      const key = clientIp(req) + '|' + v.value.email;
      const gate = loginLimiter.hit(key);
      if (!gate.allowed) { res.set('Retry-After', String(gate.retryAfterSec)); throw new HttpError(429, 'RATE_LIMITED', 'Too many failed attempts. Try again in ' + Math.ceil(gate.retryAfterSec / 60) + ' minute(s).'); }
      const user = store.findUserByEmail(v.value.email);
      const ok = await bcrypt.compare(v.value.password, user ? user.password_hash : DUMMY_HASH);
      if (!user || !ok) throw new HttpError(401, 'BAD_CREDENTIALS', 'Incorrect email or password.');   // same message for both cases: no account guessing
      loginLimiter.reset(key);
      const old = currentSession(req);
      if (old) store.deleteSession(old.id);               // fresh session on login (prevents session fixation)
      const csrfToken = startSession(res, user.id);
      res.json({ user: publicUser(user), csrfToken });
    } catch (e) { next(e); }
  });

  app.post('/api/logout', requireAuth, (req, res) => {
    store.deleteSession(req.session.id);                  // really ends the session on the server, not just in the browser
    res.clearCookie(SESSION_COOKIE, { httpOnly: true, sameSite: 'strict', secure: o.production, path: '/' });
    res.json({ ok: true });
  });

  /* ---------- 5. Notes (every query is scoped to the logged-in user) ---------- */
  const noteOut = (n) => ({ id: n.id, title: n.title, body: n.body, createdAt: n.created_at, updatedAt: n.updated_at });
  const idOr404 = (raw) => { const id = V.parseId(raw); if (!id) throw new HttpError(404, 'NOT_FOUND', 'Note not found.'); return id; };

  app.get('/api/notes', requireAuth, (req, res, next) => {
    try {
      const s = V.validateSearch(req.query.q);
      if (!s.ok) fail(s);
      res.json({ notes: store.listNotes(req.session.user_id, s.value).map(noteOut) });
    } catch (e) { next(e); }
  });

  app.post('/api/notes', requireAuth, (req, res, next) => {
    try {
      const v = V.validateNote(req.body);
      if (!v.ok) fail(v);
      if (store.countNotes(req.session.user_id) >= MAX_NOTES_PER_USER) throw new HttpError(409, 'LIMIT', 'You have reached the limit of ' + MAX_NOTES_PER_USER + ' notes.');
      res.status(201).json({ note: noteOut(store.createNote(req.session.user_id, v.value.title, v.value.body, o.now())) });
    } catch (e) { next(e); }
  });

  app.put('/api/notes/:id', requireAuth, (req, res, next) => {
    try {
      const id = idOr404(req.params.id);
      const v = V.validateNote(req.body);
      if (!v.ok) fail(v);
      const n = store.updateNote(req.session.user_id, id, v.value.title, v.value.body, o.now());
      if (!n) throw new HttpError(404, 'NOT_FOUND', 'Note not found.');     // also what you get for someone else's note
      res.json({ note: noteOut(n) });
    } catch (e) { next(e); }
  });

  app.delete('/api/notes/:id', requireAuth, (req, res, next) => {
    try {
      const id = idOr404(req.params.id);
      if (!store.deleteNote(req.session.user_id, id)) throw new HttpError(404, 'NOT_FOUND', 'Note not found.');
      res.json({ ok: true });
    } catch (e) { next(e); }
  });

  app.all('/api/*', (req, res, next) => next(new HttpError(404, 'NOT_FOUND', 'No such API route.')));

  /* ---------- 6. Static files ---------- */
  app.use(express.static(path.join(__dirname, '..', 'public'), { dotfiles: 'ignore', index: 'index.html', maxAge: 0, etag: true }));

  /* ---------- 7. Errors: clear for the user, nothing internal leaks ---------- */
  // eslint-disable-next-line no-unused-vars
  app.use((err, req, res, next) => {
    if (err instanceof HttpError) return res.status(err.status).json({ error: { code: err.code, message: err.message, fields: err.fields || undefined } });
    if (err && err.type === 'entity.parse.failed') return res.status(400).json({ error: { code: 'BAD_JSON', message: 'The request body is not valid JSON.' } });
    if (err && err.type === 'entity.too.large') return res.status(413).json({ error: { code: 'TOO_LARGE', message: 'The request is too large.' } });
    if (!o.quiet) console.error('Unexpected error:', err && err.message);   // message only, never the stack or SQL, and never sent to the client
    res.status(500).json({ error: { code: 'SERVER_ERROR', message: 'Something went wrong on our side. Please try again.' } });
  });

  return { app, store, close: () => store.close() };
}

module.exports = { createApp, HttpError };
