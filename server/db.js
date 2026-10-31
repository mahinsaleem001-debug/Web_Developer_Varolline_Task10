/* SecureNotes: database layer (SQLite).
   SQL INJECTION RULE: every value reaches SQL through a `?` placeholder in a prepared statement.
   User input is never joined into an SQL string. All statements live in this file so they are easy to review. */
const fs = require('fs');
const path = require('path');
const { DatabaseSync } = require('node:sqlite');   // built into Node 22.13+: nothing native to install or compile

const SCHEMA = `
CREATE TABLE IF NOT EXISTS users (
  id            INTEGER PRIMARY KEY AUTOINCREMENT,
  email         TEXT    NOT NULL UNIQUE COLLATE NOCASE CHECK (length(email) BETWEEN 3 AND 254),
  name          TEXT    NOT NULL CHECK (length(name) BETWEEN 2 AND 50),
  password_hash TEXT    NOT NULL,
  created_at    INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS sessions (
  id         TEXT    PRIMARY KEY,                       -- SHA-256 of the cookie token (the token itself is never stored)
  user_id    INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  csrf_token TEXT    NOT NULL,
  created_at INTEGER NOT NULL,
  expires_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS notes (
  id         INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id    INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  title      TEXT    NOT NULL CHECK (length(title) BETWEEN 1 AND 100),
  body       TEXT    NOT NULL DEFAULT '' CHECK (length(body) <= 5000),
  created_at INTEGER NOT NULL,
  updated_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_notes_user ON notes (user_id, updated_at DESC);
CREATE INDEX IF NOT EXISTS idx_sessions_user ON sessions (user_id);
`;

const MAX_NOTES_PER_USER = 200;

// LIKE treats % and _ as wildcards. Escape them so a search for "50%" means the literal text.
const escapeLike = (s) => s.replace(/[\\%_]/g, (c) => '\\' + c);

function openDb(file) {
  if (file !== ':memory:') fs.mkdirSync(path.dirname(path.resolve(file)), { recursive: true });
  const db = new DatabaseSync(file);
  db.exec('PRAGMA journal_mode = WAL;');
  db.exec('PRAGMA foreign_keys = ON;');
  db.exec(SCHEMA);

  const q = {
    insertUser: db.prepare('INSERT INTO users (email, name, password_hash, created_at) VALUES (?, ?, ?, ?)'),
    userByEmail: db.prepare('SELECT id, email, name, password_hash FROM users WHERE email = ?'),
    userById: db.prepare('SELECT id, email, name FROM users WHERE id = ?'),

    insertSession: db.prepare('INSERT INTO sessions (id, user_id, csrf_token, created_at, expires_at) VALUES (?, ?, ?, ?, ?)'),
    sessionById: db.prepare(`SELECT s.id, s.user_id, s.csrf_token, s.expires_at, u.email, u.name
                             FROM sessions s JOIN users u ON u.id = s.user_id WHERE s.id = ?`),
    deleteSession: db.prepare('DELETE FROM sessions WHERE id = ?'),
    deleteUserSessions: db.prepare('DELETE FROM sessions WHERE user_id = ?'),
    deleteExpired: db.prepare('DELETE FROM sessions WHERE expires_at <= ?'),

    notesAll: db.prepare('SELECT id, title, body, created_at, updated_at FROM notes WHERE user_id = ? ORDER BY updated_at DESC, id DESC LIMIT 200'),
    notesSearch: db.prepare(`SELECT id, title, body, created_at, updated_at FROM notes
                             WHERE user_id = ? AND (title LIKE ? ESCAPE '\\' OR body LIKE ? ESCAPE '\\')
                             ORDER BY updated_at DESC, id DESC LIMIT 200`),
    noteCount: db.prepare('SELECT COUNT(*) AS n FROM notes WHERE user_id = ?'),
    // Every note query includes user_id, so one user can never touch another user's note (no IDOR).
    noteGet: db.prepare('SELECT id, title, body, created_at, updated_at FROM notes WHERE id = ? AND user_id = ?'),
    noteInsert: db.prepare('INSERT INTO notes (user_id, title, body, created_at, updated_at) VALUES (?, ?, ?, ?, ?)'),
    noteUpdate: db.prepare('UPDATE notes SET title = ?, body = ?, updated_at = ? WHERE id = ? AND user_id = ?'),
    noteDelete: db.prepare('DELETE FROM notes WHERE id = ? AND user_id = ?')
  };

  return {
    raw: db,
    close: () => db.close(),

    createUser: (email, name, hash, now) => Number(q.insertUser.run(email, name, hash, now).lastInsertRowid),
    findUserByEmail: (email) => q.userByEmail.get(email),
    findUserById: (id) => q.userById.get(id),

    createSession: (idHash, userId, csrf, now, expires) => { q.insertSession.run(idHash, userId, csrf, now, expires); },
    findSession: (idHash) => q.sessionById.get(idHash),
    deleteSession: (idHash) => { q.deleteSession.run(idHash); },
    deleteUserSessions: (userId) => { q.deleteUserSessions.run(userId); },
    deleteExpiredSessions: (now) => q.deleteExpired.run(now).changes,

    listNotes(userId, search) {
      if (!search) return q.notesAll.all(userId);
      const like = '%' + escapeLike(search) + '%';
      return q.notesSearch.all(userId, like, like);
    },
    countNotes: (userId) => q.noteCount.get(userId).n,
    getNote: (userId, id) => q.noteGet.get(id, userId),
    createNote(userId, title, body, now) {
      const id = Number(q.noteInsert.run(userId, title, body, now, now).lastInsertRowid);
      return q.noteGet.get(id, userId);
    },
    updateNote(userId, id, title, body, now) {
      if (!q.noteUpdate.run(title, body, now, id, userId).changes) return null;
      return q.noteGet.get(id, userId);
    },
    deleteNote: (userId, id) => q.noteDelete.run(id, userId).changes > 0
  };
}

module.exports = { openDb, escapeLike, MAX_NOTES_PER_USER };
