// Test helper: starts a fresh app (in-memory database) on a random port and gives each test a client with its own cookie jar.
const { createApp } = require('../../server/app');

async function startApp(opts = {}) {
  const made = createApp(Object.assign({ dbFile: ':memory:', bcryptCost: 4, quiet: true }, opts));
  const server = await new Promise((resolve) => { const s = made.app.listen(0, '127.0.0.1', () => resolve(s)); });
  const base = 'http://127.0.0.1:' + server.address().port;

  function client() {
    const c = { cookie: '', csrf: null, base };
    c.call = async (method, url, body, extra = {}) => {
      const headers = Object.assign({ Accept: 'application/json' }, extra.headers || {});
      if (extra.plain !== true) headers['X-Requested-With'] = 'securenotes';
      if (body !== undefined && !headers['Content-Type']) headers['Content-Type'] = 'application/json';
      if (c.cookie) headers.Cookie = c.cookie;
      if (c.csrf && method !== 'GET' && extra.noCsrf !== true) headers['X-CSRF-Token'] = c.csrf;
      const res = await fetch(base + url, { method, headers, body: body === undefined ? undefined : (typeof body === 'string' ? body : JSON.stringify(body)), redirect: 'manual' });
      const set = res.headers.getSetCookie ? res.headers.getSetCookie() : [];
      set.forEach((line) => { const [pair] = line.split(';'); const [k, v] = pair.split('='); c.cookie = v ? k + '=' + v : ''; });
      let json = null; try { json = await res.json(); } catch (e) { /* not json */ }
      if (json && json.csrfToken) c.csrf = json.csrfToken;
      return { status: res.status, body: json, headers: res.headers, setCookie: set };
    };
    c.signup = (email = 'ann@example.com', name = 'Ann Lee', password = 'correct horse 9') => c.call('POST', '/api/signup', { name, email, password });
    c.login = (email = 'ann@example.com', password = 'correct horse 9') => c.call('POST', '/api/login', { email, password });
    return c;
  }
  return { ...made, base, client, stop: () => new Promise((r) => server.close(() => { made.close(); r(); })) };
}
module.exports = { startApp };
