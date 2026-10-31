const { test, expect } = require('@playwright/test');

const PASSWORD = 'correct horse 9';
let counter = 0;
const uniqueEmail = (tag) => tag + '-' + Date.now() + '-' + (counter++) + '@example.com';

async function signUp(page, { name = 'Test User', email = uniqueEmail('user'), password = PASSWORD } = {}) {
  await page.goto('/');
  await page.getByRole('tab', { name: 'Sign up' }).click();
  await page.getByLabel('Name').fill(name);
  await page.getByLabel('Email').fill(email);
  await page.getByLabel('Password', { exact: true }).fill(password);
  await page.getByRole('button', { name: 'Create account' }).click();
  await expect(page.getByRole('heading', { name: 'Your notes' })).toBeVisible();
  return { name, email, password };
}
async function addNote(page, title, body = '') {
  await page.getByRole('button', { name: 'New note' }).click();
  await page.getByLabel('Title').fill(title);
  if (body) await page.getByLabel('Text').fill(body);
  await page.getByRole('button', { name: 'Save note' }).click();
  await expect(page.locator('dialog#note-dlg')).not.toBeVisible();
}

/* 1 ---------------------------------------------------------------- core flow + auth */
test('sign up, create, edit, search and delete a note, then log out and log back in', async ({ page }) => {
  const user = await signUp(page, { name: 'Ayesha Khan' });
  await expect(page.getByText('Welcome, Ayesha Khan')).toBeVisible();

  await addNote(page, 'Shopping list', 'milk\neggs');
  await addNote(page, 'Ideas', 'build a secure app');
  await expect(page.locator('.note')).toHaveCount(2);

  await page.getByRole('button', { name: 'Edit note: Shopping list' }).click();
  await page.getByLabel('Title').fill('Groceries');
  await page.getByRole('button', { name: 'Save note' }).click();
  await expect(page.getByRole('heading', { name: 'Groceries' })).toBeVisible();

  await page.getByLabel('Search your notes').fill('secure');
  await expect(page.locator('.note')).toHaveCount(1);
  await expect(page.getByRole('heading', { name: 'Ideas' })).toBeVisible();
  await page.getByLabel('Search your notes').fill('');
  await expect(page.locator('.note')).toHaveCount(2);

  await page.getByRole('button', { name: 'Delete note: Groceries' }).click();
  await page.getByRole('button', { name: 'Delete', exact: true }).click();
  await expect(page.locator('.note')).toHaveCount(1);

  // The logged-in session survives a page reload, and logging out really ends it.
  await page.reload();
  await expect(page.getByRole('heading', { name: 'Your notes' })).toBeVisible();
  await page.getByRole('button', { name: 'Log out' }).click();
  await expect(page.getByRole('tab', { name: 'Log in' })).toBeVisible();
  expect((await page.request.get('/api/notes')).status()).toBe(401);

  await page.getByLabel('Email').fill(user.email);
  await page.getByLabel('Password', { exact: true }).fill('wrong password 1');
  await page.getByRole('button', { name: 'Log in' }).click();
  await expect(page.getByRole('alert').filter({ hasText: 'Incorrect email or password' })).toBeVisible();
  await page.getByLabel('Password', { exact: true }).fill(user.password);
  await page.getByRole('button', { name: 'Log in' }).click();
  await expect(page.getByRole('heading', { name: 'Ideas' })).toBeVisible();
});

/* 2 ---------------------------------------------------------------- XSS */
test('XSS: script and HTML in notes and in the search box are shown as text and never run', async ({ page }) => {
  const dialogs = [];
  page.on('dialog', (d) => { dialogs.push(d.message()); d.dismiss(); });
  await page.addInitScript(() => { window.__xss = 0; });

  await signUp(page);
  const payloads = [
    '<img src=x onerror="window.__xss=1;alert(1)">',
    '<script>window.__xss=1;alert(2)</script>',
    '"><svg onload="window.__xss=1;alert(3)">',
    '<a href="javascript:window.__xss=1">click</a>'
  ];
  for (const p of payloads) await addNote(page, p, p);

  await expect(page.locator('.note')).toHaveCount(payloads.length);
  for (const p of payloads) await expect(page.locator('.note-title', { hasText: p }).first()).toHaveText(p);   // shown literally
  expect(await page.locator('.note img, .note svg, .note script, .note a').count()).toBe(0);                     // no tags were created
  const attack = '<svg/onload="window.__xss=1">';
  await page.getByLabel('Search your notes').fill(attack);
  await expect(page.locator('#empty-text')).toContainText(attack);                                                // search text is text too
  expect(await page.locator('#empty img').count()).toBe(0);

  // Defence in depth: even if a script tag DID get into the page, the Content Security Policy refuses to run it.
  const violations = await page.evaluate(() => new Promise((resolve) => {
    let n = 0;
    document.addEventListener('securitypolicyviolation', () => { n += 1; });
    const s = document.createElement('script'); s.textContent = 'window.__xss = 1';
    document.body.appendChild(s);
    setTimeout(() => resolve(n), 300);
  }));
  expect(violations).toBeGreaterThan(0);
  expect(await page.evaluate(() => window.__xss)).toBe(0);
  expect(dialogs).toEqual([]);
});

/* 3 ---------------------------------------------------------------- CSRF */
test('CSRF: forged requests are rejected, including ones sent from another website', async ({ page, context }) => {
  await signUp(page);
  await addNote(page, 'Keep me');

  // (a) Requests that miss a protection are refused by the server.
  const noHeader = await page.request.post('/api/notes', { data: { title: 'forged' } });
  expect(noHeader.status()).toBe(403);
  const noToken = await page.request.post('/api/notes', { data: { title: 'forged' }, headers: { 'X-Requested-With': 'securenotes' } });
  expect(noToken.status()).toBe(403);
  expect((await noToken.json()).error.code).toBe('CSRF_TOKEN');
  const { csrfToken } = await (await page.request.get('/api/session')).json();
  const wrongSite = await page.request.post('/api/notes', { data: { title: 'forged' }, headers: { 'X-Requested-With': 'securenotes', 'X-CSRF-Token': csrfToken, Origin: 'http://evil.test' } });
  expect(wrongSite.status()).toBe(403);
  expect((await wrongSite.json()).error.code).toBe('CSRF_ORIGIN');

  // (b) A real "evil website" in the same browser tries a hidden form post and a fetch that includes our cookies.
  await context.route('http://evil.test/**', (route) => route.fulfill({
    contentType: 'text/html',
    body: `<form id="f" method="POST" action="http://localhost:3100/api/notes" enctype="text/plain">
             <input name='{"title":"Hacked","body":"x","ignore":"' value='"}'></form>
           <script>
             fetch('http://localhost:3100/api/notes', { method: 'POST', credentials: 'include', headers: { 'Content-Type': 'application/json' }, body: '{"title":"Hacked"}' })
               .then(() => { window.fetchResult = 'sent'; }).catch(() => { window.fetchResult = 'blocked'; });
             document.getElementById('f').submit();
           </script>`
  }));
  const evil = await context.newPage();
  await evil.goto('http://evil.test/attack');
  await evil.waitForTimeout(800);
  await evil.close();

  // The victim's notes are unchanged.
  await page.reload();
  await expect(page.locator('.note')).toHaveCount(1);
  await expect(page.getByRole('heading', { name: 'Keep me' })).toBeVisible();
  await expect(page.getByRole('heading', { name: 'Hacked' })).toHaveCount(0);

  // (c) The real app still works, because it sends the secret token for you.
  await addNote(page, 'Second note');
  await expect(page.locator('.note')).toHaveCount(2);
});

/* 4 ---------------------------------------------------------------- SQL injection */
test('SQL injection: attack strings do not log in, leak other people\'s data or damage the database', async ({ page, browser }) => {
  // A victim with a private note.
  const victimCtx = await browser.newContext();
  const victim = await victimCtx.newPage();
  await signUp(victim, { name: 'Victim One' });
  await addNote(victim, 'Victim secret', 'bank pin 1234');

  // The attacker has an account too, and tries the classics.
  const attacker = await signUp(page, { name: 'Mallory Eve' });
  await page.getByRole('button', { name: 'Log out' }).click();
  await page.getByLabel('Email').fill("' OR '1'='1' --");
  await page.getByLabel('Password', { exact: true }).fill('x');
  await page.getByRole('button', { name: 'Log in' }).click();
  await expect(page.getByText('Enter a valid email address')).toBeVisible();      // stopped by the browser check

  const viaApi = await page.request.post('/api/login', { data: { email: "' OR '1'='1' --@x.co", password: 'x' }, headers: { 'X-Requested-With': 'securenotes' } });
  expect(viaApi.status()).toBe(400);                                              // and the server checks again
  const classic = await page.request.post('/api/login', { data: { email: attacker.email, password: "' OR '1'='1" }, headers: { 'X-Requested-With': 'securenotes' } });
  expect(classic.status()).toBe(401);

  await page.getByLabel('Email').fill(attacker.email);
  await page.getByLabel('Password', { exact: true }).fill(attacker.password);
  await page.getByRole('button', { name: 'Log in' }).click();
  await expect(page.getByRole('heading', { name: 'Your notes' })).toBeVisible();

  await addNote(page, "'; DROP TABLE notes; --", 'harmless text');
  for (const q of ["' OR '1'='1", "%' UNION SELECT body FROM notes --", '"; DELETE FROM users; --']) {
    await page.getByLabel('Search your notes').fill(q);
    await expect(page.getByRole('heading', { name: 'No notes match' })).toBeVisible();
    await expect(page.getByText('Victim secret')).toHaveCount(0);
  }
  await page.getByLabel('Search your notes').fill('');
  await expect(page.getByRole('heading', { name: "'; DROP TABLE notes; --" })).toBeVisible();   // stored as plain text, nothing was dropped

  // The victim's data is intact and still works.
  await victim.reload();
  await expect(victim.getByRole('heading', { name: 'Victim secret' })).toBeVisible();
  await victimCtx.close();
});

/* 5 ---------------------------------------------------------------- validation, client + server */
test('validation: the browser stops bad input before sending, and the server rejects the same input', async ({ page }) => {
  const requests = [];
  page.on('request', (r) => { if (r.url().includes('/api/signup')) requests.push(r.url()); });
  await page.goto('/');
  await page.getByRole('tab', { name: 'Sign up' }).click();
  await page.getByLabel('Name').fill('<b>Bad</b>');
  await page.getByLabel('Email').fill('not-an-email');
  await page.getByLabel('Password', { exact: true }).fill('short');
  await page.getByRole('button', { name: 'Create account' }).click();

  await expect(page.locator('#e-name')).toContainText('letters');
  await expect(page.locator('#e-email')).toContainText('valid email');
  await expect(page.locator('#e-password')).toContainText('at least 10');
  await expect(page.getByLabel('Email')).toHaveAttribute('aria-invalid', 'true');
  expect(requests).toHaveLength(0);                                               // nothing was sent to the server

  // Someone who skips the browser check and calls the API directly is stopped by the server.
  const direct = await page.request.post('/api/signup', { data: { name: '<b>Bad</b>', email: 'not-an-email', password: 'short' }, headers: { 'X-Requested-With': 'securenotes' } });
  expect(direct.status()).toBe(400);
  const body = await direct.json();
  expect(Object.keys(body.error.fields).sort()).toEqual(['email', 'name', 'password']);

  // Notes are validated the same way.
  await page.getByLabel('Name').fill('Valid Name');
  await page.getByLabel('Email').fill(uniqueEmail('valid'));
  await page.getByLabel('Password', { exact: true }).fill(PASSWORD);
  await page.getByRole('button', { name: 'Create account' }).click();
  await expect(page.getByRole('heading', { name: 'Your notes' })).toBeVisible();
  await page.getByRole('button', { name: 'New note' }).click();
  await page.getByRole('button', { name: 'Save note' }).click();
  await expect(page.locator('#e-title')).toContainText('Give the note a title');
  await expect(page.locator('dialog#note-dlg')).toBeVisible();
});

/* 6 ---------------------------------------------------------------- headers and cookies */
test('secure headers are set and the session cookie cannot be read by scripts', async ({ page, context }) => {
  const res = await page.goto('/');
  const h = res.headers();
  expect(h['content-security-policy']).toContain("script-src 'self'");
  expect(h['content-security-policy']).toContain("frame-ancestors 'none'");
  expect(h['content-security-policy']).not.toMatch(/unsafe-inline|unsafe-eval/);
  expect(h['x-content-type-options']).toBe('nosniff');
  expect(h['x-frame-options']).toBe('DENY');
  expect(h['referrer-policy']).toBe('no-referrer');
  expect(h['permissions-policy']).toContain('camera=()');
  expect(h['x-powered-by']).toBeUndefined();

  await signUp(page);
  const cookie = (await context.cookies()).find((c) => c.name === 'sid');
  expect(cookie.httpOnly).toBe(true);
  expect(cookie.sameSite).toBe('Strict');
  expect(await page.evaluate(() => document.cookie)).not.toContain('sid');        // JavaScript (and so XSS) cannot read it
  const api = await page.request.get('/api/notes');
  expect(api.headers()['cache-control']).toBe('no-store');
});

/* 7 ---------------------------------------------------------------- access control */
test('access control: one user can never see or change another user\'s notes', async ({ browser }) => {
  const aCtx = await browser.newContext(), bCtx = await browser.newContext();
  const a = await aCtx.newPage(), b = await bCtx.newPage();
  await signUp(a, { name: 'Alice Doe' });
  await addNote(a, 'Alice private note', 'only for Alice');
  await signUp(b, { name: 'Bob Roe' });

  await expect(b.getByText('Alice private note')).toHaveCount(0);
  await expect(b.getByRole('heading', { name: 'No notes yet' })).toBeVisible();

  const aliceNotes = await (await a.request.get('/api/notes')).json();
  const id = aliceNotes.notes[0].id;
  const { csrfToken } = await (await b.request.get('/api/session')).json();
  const headers = { 'X-Requested-With': 'securenotes', 'X-CSRF-Token': csrfToken };
  expect((await b.request.put('/api/notes/' + id, { data: { title: 'Hacked' }, headers })).status()).toBe(404);
  expect((await b.request.delete('/api/notes/' + id, { headers })).status()).toBe(404);

  await a.reload();
  await expect(a.getByRole('heading', { name: 'Alice private note' })).toBeVisible();
  await aCtx.close(); await bCtx.close();
});
