/* SecureNotes: small, separately testable security helpers. */
const crypto = require('crypto');

const sha256 = (s) => crypto.createHash('sha256').update(s).digest('hex');
const newToken = (bytes = 32) => crypto.randomBytes(bytes).toString('base64url');

// Compare two secrets without leaking where they differ (timing attack protection).
function safeEqual(a, b) {
  if (typeof a !== 'string' || typeof b !== 'string') return false;
  const ha = crypto.createHash('sha256').update(a).digest();
  const hb = crypto.createHash('sha256').update(b).digest();
  return crypto.timingSafeEqual(ha, hb) && a.length === b.length;
}

function parseCookies(header) {
  const out = Object.create(null);
  if (!header || typeof header !== 'string') return out;
  header.split(';').forEach((part) => {
    const i = part.indexOf('=');
    if (i < 1) return;
    const k = part.slice(0, i).trim();
    let v = part.slice(i + 1).trim();
    try { v = decodeURIComponent(v); } catch (e) { return; }
    if (!(k in out)) out[k] = v;
  });
  return out;
}

/* Allow only requests that come from our own site. A browser always sends Origin on cross-site POSTs,
   so a mismatch is a CSRF attempt. (No Origin = not a browser form or fetch, e.g. curl; the other CSRF checks still apply.) */
function originAllowed(req) {
  const origin = req.headers.origin;
  if (!origin) return true;
  try { return new URL(origin).host === req.headers.host; } catch (e) { return false; }
}

// Fixed-window limiter, in memory. Good enough for one server; use Redis if you run several.
function createLimiter({ windowMs, max, now = () => Date.now() }) {
  const hits = new Map();
  const sweep = () => { const t = now(); for (const [k, v] of hits) if (v.reset <= t) hits.delete(k); };
  return {
    // returns { allowed, retryAfterSec }
    hit(key) {
      if (hits.size > 5000) sweep();
      const t = now();
      let e = hits.get(key);
      if (!e || e.reset <= t) { e = { count: 0, reset: t + windowMs }; hits.set(key, e); }
      e.count += 1;
      return { allowed: e.count <= max, retryAfterSec: Math.max(1, Math.ceil((e.reset - t) / 1000)) };
    },
    reset(key) { hits.delete(key); },
    size: () => hits.size
  };
}

module.exports = { sha256, newToken, safeEqual, parseCookies, originAllowed, createLimiter };
