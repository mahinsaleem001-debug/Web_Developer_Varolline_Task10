const test = require('node:test');
const assert = require('node:assert/strict');
const V = require('../../public/js/validate.js');

const goodSignup = { name: 'Ann Lee', email: 'Ann@Example.com ', password: 'correct horse 9' };

test('signup: a good form passes and the email is lower-cased and trimmed', () => {
  const r = V.validateSignup(goodSignup);
  assert.equal(r.ok, true);
  assert.equal(r.value.email, 'ann@example.com');
});
test('signup: names use an allow-list (letters, spaces, . \' -)', () => {
  for (const n of ['Zoë Müller', "O'Brien", 'Anne-Marie', 'محمد علي', 'J. Smith']) assert.equal(V.validateSignup({ ...goodSignup, name: n }).ok, true, n);
  for (const n of ['<script>', 'Ann<b>', 'a', '1234', '"; DROP TABLE users;--', 'x'.repeat(51)]) assert.ok(V.validateSignup({ ...goodSignup, name: n }).errors.name, n);
});
test('signup: bad emails are rejected', () => {
  for (const e of ['', 'plain', 'a@b', '@x.com', 'a b@x.com', 'a"b@x.com', 'a@x..', '<a@x.com', 'a'.repeat(65) + '@x.com', 'a@' + 'b'.repeat(250) + '.com'])
    assert.ok(V.validateSignup({ ...goodSignup, email: e }).errors.email, JSON.stringify(e));
});
test('signup: password rules (length, letter + number, common list, bcrypt 72-byte limit)', () => {
  assert.ok(V.validateSignup({ ...goodSignup, password: 'short1' }).errors.password);
  assert.ok(V.validateSignup({ ...goodSignup, password: 'onlyletterspassword' }).errors.password);
  assert.ok(V.validateSignup({ ...goodSignup, password: '1234567890' }).errors.password);
  assert.ok(V.validateSignup({ ...goodSignup, password: 'password123' }).errors.password);
  assert.ok(V.validateSignup({ ...goodSignup, password: 'a1'.repeat(37) }).errors.password, '74 bytes is too long');
  assert.equal(V.validateSignup({ ...goodSignup, password: 'a1'.repeat(36) }).ok, true, '72 bytes is fine');
  assert.ok(V.validateSignup({ ...goodSignup, password: 'é1'.repeat(25) }).errors.password, 'counts bytes, not characters');
});
test('signup: wrong types do not crash', () => {
  for (const bad of [null, undefined, 5, 'x', [], { name: {}, email: [], password: 1 }]) assert.equal(V.validateSignup(bad).ok, false);
});
test('login: needs a valid email and any non-empty password', () => {
  assert.equal(V.validateLogin({ email: 'a@b.co', password: 'x' }).ok, true);
  assert.ok(V.validateLogin({ email: "' OR '1'='1", password: 'x' }).errors.email);
  assert.ok(V.validateLogin({ email: 'a@b.co', password: '' }).errors.password);
  assert.ok(V.validateLogin({ email: 'a@b.co', password: 'x'.repeat(300) }).errors.password);
});
test('note: title and text limits, and trimming', () => {
  assert.equal(V.validateNote({ title: '  Hello   world ', body: ' text ' }).value.title, 'Hello world');
  assert.ok(V.validateNote({ title: '', body: '' }).errors.title);
  assert.ok(V.validateNote({ title: '   ', body: '' }).errors.title);
  assert.ok(V.validateNote({ title: 'x'.repeat(101), body: '' }).errors.title);
  assert.ok(V.validateNote({ title: 'ok', body: 'x'.repeat(5001) }).errors.body);
  assert.equal(V.validateNote({ title: 'ok', body: 'x'.repeat(5000) }).ok, true);
  assert.equal(V.validateNote({ title: 'ok' }).value.body, '');
});
test('note: control characters are rejected, but newlines in the text are fine', () => {
  assert.ok(V.validateNote({ title: 'bad\u0000title', body: '' }).errors.title);
  assert.ok(V.validateNote({ title: 'ok', body: 'bad\u0007text' }).errors.body);
  assert.equal(V.validateNote({ title: 'ok', body: 'line1\r\nline2\n\tindented' }).ok, true);
  assert.equal(V.validateNote({ title: 'ok', body: 'a\r\nb' }).value.body, 'a\nb');
});
test('note: HTML and SQL are valid TEXT (they are made safe when stored and shown, not by deleting characters)', () => {
  const t = '<img src=x onerror=alert(1)>'; const b = "'; DROP TABLE notes; --";
  const r = V.validateNote({ title: t, body: b });
  assert.equal(r.ok, true); assert.equal(r.value.title, t); assert.equal(r.value.body, b);
});
test('note: non-string values are rejected', () => {
  assert.equal(V.validateNote({ title: { $gt: '' }, body: '' }).ok, false);
  assert.equal(V.validateNote({ title: 'ok', body: ['x'] }).ok, false);
  assert.equal(V.validateNote(null).ok, false);
});
test('search: limits and control characters', () => {
  assert.equal(V.validateSearch(undefined).ok, true);
  assert.equal(V.validateSearch('  hello ').value, 'hello');
  assert.ok(V.validateSearch('x'.repeat(51)).errors.q);
  assert.ok(V.validateSearch('a\u0000b').errors.q);
  assert.ok(V.validateSearch(['a']).errors.q);
});
test('parseId: only plain positive integers', () => {
  assert.equal(V.parseId('42'), 42);
  for (const bad of ['0', '-1', '1.5', '1e3', '01', ' 1', '1 OR 1=1', '1;DROP', '', null, undefined, {}, '9'.repeat(20)]) assert.equal(V.parseId(bad), null, String(bad));
});
