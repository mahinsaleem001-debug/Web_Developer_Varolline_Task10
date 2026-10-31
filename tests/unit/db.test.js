const test = require('node:test');
const assert = require('node:assert/strict');
const { openDb, escapeLike } = require('../../server/db');

function setup() {
  const db = openDb(':memory:');
  const a = db.createUser('a@x.co', 'Ann Lee', 'hash', 1);
  const b = db.createUser('b@x.co', 'Bob Ray', 'hash', 1);
  return { db, a, b };
}
const PAYLOADS = ["' OR '1'='1", "'; DROP TABLE notes; --", '" OR ""="', "1; DELETE FROM users", "%' UNION SELECT password_hash,1,1,1,1 FROM users --", '\\', "' OR 1=1 --"];

test('escapeLike: wildcards and backslash are escaped', () => { assert.equal(escapeLike('50%_off\\'), '50\\%\\_off\\\\'); });

test('SQL injection: payloads used as titles and bodies are stored as plain text', () => {
  const { db, a } = setup();
  PAYLOADS.forEach((p, i) => db.createNote(a, p.slice(0, 100) || 'x', p, 10 + i));
  assert.equal(db.listNotes(a).length, PAYLOADS.length);
  assert.equal(db.listNotes(a).find((n) => n.body === PAYLOADS[1]).body, "'; DROP TABLE notes; --");
  assert.equal(db.raw.prepare("SELECT COUNT(*) c FROM sqlite_master WHERE name IN ('users','notes','sessions')").get().c, 3, 'tables still exist');
  assert.equal(db.raw.prepare('SELECT COUNT(*) c FROM users').get().c, 2, 'users are untouched');
});
test('SQL injection: search payloads never return other people\'s notes or extra rows', () => {
  const { db, a, b } = setup();
  db.createNote(a, 'Groceries', 'milk', 1);
  db.createNote(b, 'Secret of Bob', 'bob only', 2);
  for (const p of PAYLOADS) {
    const found = db.listNotes(a, p);
    assert.ok(found.every((n) => n.title !== 'Secret of Bob'), 'payload leaked a note: ' + p);
    assert.ok(found.length <= 1);
  }
  assert.equal(db.listNotes(a, 'milk').length, 1);
});
test('SQL injection: email lookup with a payload finds nobody', () => {
  const { db } = setup();
  assert.equal(db.findUserByEmail("' OR '1'='1"), undefined);
  assert.equal(db.findUserByEmail("a@x.co' --"), undefined);
});
test('search treats % and _ as plain characters', () => {
  const { db, a } = setup();
  db.createNote(a, '100% done', '', 1); db.createNote(a, 'plain', '', 2); db.createNote(a, 'a_b', '', 3); db.createNote(a, 'axb', '', 4);
  assert.deepEqual(db.listNotes(a, '%').map((n) => n.title), ['100% done']);
  assert.deepEqual(db.listNotes(a, 'a_b').map((n) => n.title), ['a_b']);
});
test('ownership: get, update and delete only work for the owner', () => {
  const { db, a, b } = setup();
  const n = db.createNote(a, 'Mine', 'x', 1);
  assert.equal(db.getNote(b, n.id), undefined);
  assert.equal(db.updateNote(b, n.id, 'Hacked', 'x', 2), null);
  assert.equal(db.deleteNote(b, n.id), false);
  assert.equal(db.getNote(a, n.id).title, 'Mine');
  assert.equal(db.updateNote(a, n.id, 'Edited', 'y', 3).title, 'Edited');
  assert.equal(db.deleteNote(a, n.id), true);
});
test('database rules: duplicate emails (any case) and out-of-range values are refused by SQLite itself', () => {
  const { db, a } = setup();
  assert.throws(() => db.createUser('A@X.CO', 'Dup Lic', 'h', 1), /UNIQUE/);
  assert.throws(() => db.createNote(a, '', 'x', 1), /CHECK/);
  assert.throws(() => db.createNote(a, 'x'.repeat(101), 'x', 1), /CHECK/);
});
test('deleting a user removes their notes and sessions (foreign keys)', () => {
  const { db, a } = setup();
  db.createNote(a, 'n', '', 1); db.createSession('h1', a, 'c', 1, 99);
  db.raw.prepare('DELETE FROM users WHERE id = ?').run(a);
  assert.equal(db.raw.prepare('SELECT COUNT(*) c FROM notes').get().c, 0);
  assert.equal(db.findSession('h1'), undefined);
});
test('expired sessions are cleaned up', () => {
  const { db, a } = setup();
  db.createSession('old', a, 'c', 1, 5); db.createSession('new', a, 'c', 1, 500);
  assert.equal(db.deleteExpiredSessions(10), 1);
  assert.ok(db.findSession('new')); assert.equal(db.findSession('old'), undefined);
});
