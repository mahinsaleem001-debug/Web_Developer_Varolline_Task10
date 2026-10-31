# Security checklist

This file shows, risk by risk, **how SecureNotes handles it**, **where in the code**, and **which test proves it**.
Every item marked with a test name was checked by an automated test that runs in CI on every push.
To make sure the tests are real, I also removed each protection on purpose (see "How I checked the tests" at the end) and confirmed the tests fail.

Test names: **U** = unit/API test in `tests/unit/`, **E** = end-to-end Playwright test in `tests/e2e/securenotes.spec.js`.

## 1. The three required risks

| Risk | How it is handled | Where | Proven by |
|---|---|---|---|
| **XSS** (cross-site scripting): an attacker stores `<script>` or `<img onerror=...>` in a note | 1. All user text is put on the page with `textContent`, never `innerHTML`, so tags are shown as characters and never become elements.<br>2. A strict **Content Security Policy** (`script-src 'self'`, no `unsafe-inline`, no `unsafe-eval`) means that even if a tag got in, the browser refuses to run an inline script.<br>3. The page has no inline scripts, styles or `on...=` attributes, so the policy can be strict.<br>4. The API returns JSON with `X-Content-Type-Options: nosniff`.<br>5. Names are limited by an allow-list; the session cookie is `HttpOnly`, so a script could not steal it anyway. | `public/js/app.js` (`el()` helper), `server/app.js` (helmet CSP), `public/index.html` | **E** "XSS: script and HTML in notes and in the search box are shown as text and never run" (also injects a script tag and checks that the CSP blocks it), **U** "the web page itself carries the same security headers", "XSS: HTML in a note is stored as plain text" |
| **CSRF** (a malicious site makes your browser send a request to our site) | 1. Cookie is `SameSite=Strict`, so browsers do not send it from other sites.<br>2. Every request that changes data must carry a secret **per-session CSRF token** (`X-CSRF-Token`), compared in constant time. Other sites cannot read it.<br>3. Every such request must also carry the custom header `X-Requested-With`. A cross-site page cannot add it without a CORS preflight, and the server never allows CORS.<br>4. The `Origin` header must match our host.<br>5. Only JSON bodies are accepted (plain HTML forms are refused with 415).<br>6. Login and sign-up are protected too (login CSRF). | `server/app.js` (CSRF middleware and `requireAuth`), `server/security.js`, `public/js/api.js` | **E** "CSRF: forged requests are rejected, including ones sent from another website" (a real evil page in the same browser tries a hidden form and a cookie-carrying fetch), **U** seven CSRF tests in `api.test.js` (missing header, missing token, wrong token, another user's token, wrong Origin, form content-type, no CORS headers) |
| **SQL injection** | 1. **Every** query is a prepared statement with `?` placeholders. User input is never joined into SQL text. All SQL lives in one file (`server/db.js`) so it is easy to review.<br>2. `LIKE` searches escape `%`, `_` and `\` so they are plain characters.<br>3. Ids from URLs must be plain positive integers (`parseId`).<br>4. Every note query also includes `user_id`, so injection or guessing cannot reach another user's rows.<br>5. The database enforces rules itself (`UNIQUE`, `CHECK`, foreign keys).<br>6. Errors never include SQL or stack traces. | `server/db.js`, `public/js/validate.js` (`parseId`) | **U** `db.test.js` (payloads as titles, bodies, search text and emails; tables still exist; nothing leaks), **U** "login: SQL injection strings do not log anyone in", "search: SQL injection and wildcard strings are harmless", **E** "SQL injection: attack strings do not log in, leak other people's data or damage the database" |

## 2. Input validation (client and server)

| Risk | How it is handled | Where | Proven by |
|---|---|---|---|
| Bad or malicious input | One set of rules (`validate.js`) is used by the browser for instant feedback and **run again on the server**, which never trusts the browser. Rules: required fields, length limits, email format, name allow-list, password length/complexity, no control characters, wrong types rejected (e.g. objects instead of strings). | `public/js/validate.js` (shared), `server/app.js` | **U** `validate.test.js` (12 tests), **E** "validation: the browser stops bad input before sending, and the server rejects the same input" (checks that no request is sent, then calls the API directly) |
| Oversized requests | JSON body limit of 20 KB, notes limited to 5,000 characters, 200 notes per user. | `server/app.js`, `server/db.js` | **U** "notes: bad ids and bodies are rejected" (413) |

## 3. Authentication and sessions

| Risk | How it is handled | Where | Proven by |
|---|---|---|---|
| Passwords stolen from the database | Passwords are hashed with **bcrypt** (cost 12, salted). Plain passwords are never stored or logged. Maximum 72 bytes is enforced because bcrypt ignores the rest. | `server/app.js` | **U** "passwords are stored as bcrypt hashes, never as text" |
| Session theft or reuse | Random 256-bit session token in an `HttpOnly`, `SameSite=Strict` cookie (`Secure` in production). Only the **SHA-256 hash** of the token is stored, so a leaked database cannot be used to log in. Sessions expire after 24 hours and are deleted on logout (really ended on the server). | `server/app.js`, `server/db.js` | **U** "session cookie value is not stored", "logout ends the session on the server", "expired sessions stop working", **E** "secure headers are set and the session cookie cannot be read by scripts" |
| Session fixation | A new session is created at login and the old one is deleted. | `server/app.js` | **U** "login: a fresh session replaces the old one" |
| Password guessing (brute force) | Login is limited to 8 attempts per 15 minutes per address and email, then `429` with `Retry-After`. Sign-up is limited too. | `server/security.js` (`createLimiter`), `server/app.js` | **U** "login: after too many failures the account is rate limited", "signup is rate limited per address", limiter unit test |
| Account guessing (which emails exist) | Wrong password and unknown email give the **same message**, and an unknown email still runs a bcrypt check so the response time is similar. | `server/app.js` | **U** "wrong password and unknown email give the SAME message" |
| Timing attacks on tokens | Tokens are compared with `crypto.timingSafeEqual`. | `server/security.js` (`safeEqual`) | **U** "safeEqual" |

## 4. Access control

| Risk | How it is handled | Where | Proven by |
|---|---|---|---|
| One user reading or changing another user's notes (IDOR) | The note id alone is never enough: every query also filters by the logged-in `user_id`. Someone else's note returns `404`, the same as a missing note, so it does not even confirm that it exists. | `server/db.js`, `server/app.js` | **U** "access control: users cannot read, edit or delete each other's notes", `db.test.js` "ownership", **E** "access control: one user can never see or change another user's notes" |
| Reaching data without logging in | Every notes route requires a valid session. | `requireAuth` in `server/app.js` | **U** "notes need a login" |

## 5. Secure headers and browser protections

| Header or setting | Value | Protects against |
|---|---|---|
| `Content-Security-Policy` | `default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; object-src 'none'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'` (+ `upgrade-insecure-requests` in production) | XSS, data injection, clickjacking, mixed content |
| `X-Content-Type-Options` | `nosniff` | Browsers treating data as scripts |
| `X-Frame-Options` | `DENY` | Clickjacking (older browsers) |
| `Referrer-Policy` | `no-referrer` | Leaking URLs to other sites |
| `Strict-Transport-Security` | 1 year (production only) | Downgrade to plain HTTP |
| `Permissions-Policy` | camera, microphone, geolocation, payment, usb all off | Abuse of browser features |
| `Cross-Origin-Opener-Policy` / `Cross-Origin-Resource-Policy` | `same-origin` | Cross-site leaks |
| `Cache-Control: no-store` on `/api` | | Private data kept in caches |
| `X-Powered-By` | removed | Advertising the framework |
| Cookie flags | `HttpOnly`, `SameSite=Strict`, `Secure` (production) | Script access, CSRF, sniffing |

Proven by **U** "security headers are on every response", "production mode adds HSTS, upgrade-insecure-requests and the Secure cookie flag", **E** "secure headers are set and the session cookie cannot be read by scripts".

## 6. Other risks

| Risk | How it is handled | Proven by |
|---|---|---|
| Leaking internal details in errors | One error handler: users get a clear message and a code; stack traces, file paths and SQL are only logged on the server (message only). | **U** "errors do not leak internals" |
| Exposed files | Only the `public/` folder is served; dotfiles are ignored; the database and server code are not reachable. | **U** "hidden files and the database are not served" |
| Vulnerable dependencies | `npm audit` runs in CI and fails the build on high or critical issues. Few dependencies (express, bcryptjs, helmet); the SQLite driver is built into Node. | CI job **Dependency security audit** |
| Secrets in the code | There are none in the repo. Configuration comes from environment variables (`.env.example` lists them); `.env` and the database are in `.gitignore`. | Code review |
| Code changes breaking security | CI runs all unit and end-to-end tests on every push and pull request. | `.github/workflows/ci.yml` |

## 7. Known limits (honest list)

- **HTTPS is not provided by the app.** Use a host that serves HTTPS (Render, Fly, Nginx, Caddy) and set `NODE_ENV=production` so cookies become `Secure` and HSTS is sent. Set `TRUST_PROXY=1` when running behind such a proxy.
- The rate limiter is **in memory**, so it resets on restart and is per server. Use Redis for several servers.
- No email verification, password reset or two-factor login. These are the next features I would add.
- Sign-up tells the user if an email already exists (a common trade-off for friendly sign-up). Login does not.
- The CSRF token is returned by `GET /api/session`. It is protected by `SameSite=Strict` and the same-origin rule, which is the standard approach for a single-page app.
- No audit log of security events.

## How I checked the tests

A test that cannot fail proves nothing. I temporarily removed three protections and confirmed the tests caught it, then restored them:

1. Switched note rendering from `textContent` to `innerHTML`, and the XSS end-to-end test failed.
2. Removed the CSRF token, header and origin checks, and the CSRF end-to-end test failed.
3. Built one SQL query by joining strings, and the SQL injection unit test failed.
