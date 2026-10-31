/* SecureNotes: input validation shared by the browser and the server.
   The browser uses it for quick feedback. The server runs the SAME rules again,
   because anything coming from a browser can be faked. Never trust the client alone. */
(function (root, factory) {
  if (typeof module === 'object' && module.exports) module.exports = factory();
  else root.Validate = factory();
})(typeof self !== 'undefined' ? self : this, function () {
  'use strict';

  const LIMITS = { nameMin: 2, nameMax: 50, emailMax: 254, pwMin: 10, pwMax: 72, titleMax: 100, bodyMax: 5000, searchMax: 50 };

  // Allow-list for names: letters (any language), spaces, dots, apostrophes and hyphens. No < > & " etc.
  const NAME_RE = /^[\p{L}\p{M}][\p{L}\p{M} .'’-]*$/u;
  const EMAIL_RE = /^[^\s@<>()[\]\\,;:"]{1,64}@[^\s@<>()[\]\\,;:"]+\.[^\s@<>()[\]\\,;:"]{2,}$/;
  // Control characters are never valid input (newline and tab are allowed in note text only).
  const CTRL_RE = /[\u0000-\u0008\u000B\u000C\u000E-\u001F\u007F]/;
  const CTRL_NO_NL_RE = /[\u0000-\u001F\u007F]/;
  const COMMON = ['password', 'password1', 'password123', '1234567890', 'qwertyuiop', 'letmein123', 'iloveyou123', 'admin12345'];

  const isStr = (v) => typeof v === 'string';
  const byteLength = (s) => new TextEncoder().encode(s).length;   // bcrypt only reads the first 72 BYTES
  const norm = (s) => s.normalize('NFC').trim();

  function result(value, errors) { return { ok: Object.keys(errors).length === 0, value, errors }; }

  function email(v, errors) {
    if (!isStr(v) || !v.trim()) { errors.email = 'Enter your email address.'; return ''; }
    const e = norm(v).toLowerCase();
    if (e.length > LIMITS.emailMax || !EMAIL_RE.test(e) || CTRL_NO_NL_RE.test(e)) errors.email = 'Enter a valid email address, like name@example.com.';
    return e;
  }

  function validateSignup(input) {
    const i = input || {}, errors = {};
    const out = { email: email(i.email, errors), name: '', password: '' };

    if (!isStr(i.name) || !i.name.trim()) errors.name = 'Enter your name.';
    else {
      out.name = norm(i.name).replace(/\s+/g, ' ');
      if (out.name.length < LIMITS.nameMin) errors.name = 'Name must be at least ' + LIMITS.nameMin + ' characters.';
      else if (out.name.length > LIMITS.nameMax) errors.name = 'Name must be at most ' + LIMITS.nameMax + ' characters.';
      else if (!NAME_RE.test(out.name)) errors.name = 'Use letters, spaces, dots, apostrophes and hyphens only.';
    }

    const p = i.password;
    if (!isStr(p) || !p) errors.password = 'Choose a password.';
    else {
      out.password = p;                                   // passwords are never trimmed or changed
      if (p.length < LIMITS.pwMin) errors.password = 'Password must be at least ' + LIMITS.pwMin + ' characters.';
      else if (byteLength(p) > LIMITS.pwMax) errors.password = 'Password is too long (maximum ' + LIMITS.pwMax + ' bytes).';
      else if (!/[A-Za-z\p{L}]/u.test(p) || !/\d/.test(p)) errors.password = 'Use at least one letter and one number.';
      else if (COMMON.includes(p.toLowerCase()) || (out.email && p.toLowerCase() === out.email)) errors.password = 'That password is too easy to guess. Choose another.';
      else if (CTRL_NO_NL_RE.test(p)) errors.password = 'Password contains characters that are not allowed.';
    }
    return result(out, errors);
  }

  function validateLogin(input) {
    const i = input || {}, errors = {};
    const out = { email: email(i.email, errors), password: '' };
    if (!isStr(i.password) || !i.password) errors.password = 'Enter your password.';
    else if (byteLength(i.password) > 200) errors.password = 'Password is too long.';
    else out.password = i.password;
    return result(out, errors);
  }

  function validateNote(input) {
    const i = input || {}, errors = {};
    const out = { title: '', body: '' };
    if (!isStr(i.title) || !i.title.trim()) errors.title = 'Give the note a title.';
    else {
      out.title = norm(i.title).replace(/\s+/g, ' ');
      if (out.title.length > LIMITS.titleMax) errors.title = 'Title must be at most ' + LIMITS.titleMax + ' characters.';
      else if (CTRL_NO_NL_RE.test(out.title)) errors.title = 'Title contains characters that are not allowed.';
    }
    if (i.body === undefined || i.body === null) out.body = '';
    else if (!isStr(i.body)) errors.body = 'Text must be plain text.';
    else {
      out.body = i.body.normalize('NFC').replace(/\r\n?/g, '\n').trim();
      if (out.body.length > LIMITS.bodyMax) errors.body = 'Text must be at most ' + LIMITS.bodyMax + ' characters.';
      else if (CTRL_RE.test(out.body)) errors.body = 'Text contains characters that are not allowed.';
    }
    return result(out, errors);
  }

  function validateSearch(q) {
    const errors = {};
    if (q === undefined || q === null) return result('', errors);
    if (!isStr(q)) { errors.q = 'Search must be text.'; return result('', errors); }
    const v = norm(q);
    if (v.length > LIMITS.searchMax) errors.q = 'Search must be at most ' + LIMITS.searchMax + ' characters.';
    else if (CTRL_NO_NL_RE.test(v)) errors.q = 'Search contains characters that are not allowed.';
    return result(v, errors);
  }

  // A database id from a URL: digits only, positive, fits in a safe integer.
  function parseId(v) {
    if (typeof v !== 'string' && typeof v !== 'number') return null;
    const s = String(v);
    if (!/^[1-9]\d{0,14}$/.test(s)) return null;
    return Number(s);
  }

  return { LIMITS, validateSignup, validateLogin, validateNote, validateSearch, parseId };
});
