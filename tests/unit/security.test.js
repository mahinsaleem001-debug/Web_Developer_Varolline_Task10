const test = require('node:test');
const assert = require('node:assert/strict');
const sec = require('../../server/security');

test('sha256 and tokens: tokens are long, random and different every time', () => {
  assert.equal(sec.sha256('abc').length, 64);
  const a = sec.newToken(), b = sec.newToken();
  assert.notEqual(a, b); assert.ok(a.length >= 43);
});
test('safeEqual: equal strings only, no crash on bad types', () => {
  assert.equal(sec.safeEqual('abc', 'abc'), true);
  assert.equal(sec.safeEqual('abc', 'abd'), false);
  assert.equal(sec.safeEqual('abc', 'abcd'), false);
  assert.equal(sec.safeEqual(undefined, 'abc'), false);
  assert.equal(sec.safeEqual('abc', null), false);
});
test('parseCookies: reads values, ignores junk, first value wins', () => {
  const c = sec.parseCookies('a=1; sid=abc%20d; bad; =x; sid=second');
  assert.equal(c.a, '1'); assert.equal(c.sid, 'abc d'); assert.equal(c.bad, undefined);
  assert.deepEqual(Object.keys(sec.parseCookies(undefined)), []);
  assert.equal(sec.parseCookies('x=%E0%A4%A').x, undefined, 'bad encoding is skipped');
  assert.equal(Object.getPrototypeOf(sec.parseCookies('__proto__=x')), null, 'a cookie named __proto__ cannot pollute objects');
});
test('originAllowed: same host ok, other host blocked, missing Origin allowed', () => {
  const req = (origin, host = 'localhost:3000') => ({ headers: { origin, host } });
  assert.equal(sec.originAllowed(req('http://localhost:3000')), true);
  assert.equal(sec.originAllowed(req('http://evil.test')), false);
  assert.equal(sec.originAllowed(req('http://localhost:3000.evil.test')), false);
  assert.equal(sec.originAllowed(req('null')), false);
  assert.equal(sec.originAllowed(req(undefined)), true);
});
test('limiter: blocks after max, reports retry time, resets after the window and on reset()', () => {
  let t = 1000;
  const l = sec.createLimiter({ windowMs: 60000, max: 3, now: () => t });
  assert.equal(l.hit('k').allowed, true); assert.equal(l.hit('k').allowed, true); assert.equal(l.hit('k').allowed, true);
  const blocked = l.hit('k');
  assert.equal(blocked.allowed, false); assert.ok(blocked.retryAfterSec >= 1 && blocked.retryAfterSec <= 60);
  assert.equal(l.hit('other').allowed, true, 'other keys are separate');
  l.reset('k'); assert.equal(l.hit('k').allowed, true);
  for (let i = 0; i < 5; i++) l.hit('k');
  t += 61000; assert.equal(l.hit('k').allowed, true, 'window passed');
});
