/* SecureNotes: API client. Adds the CSRF protection headers to every request and turns failures into clear errors. */
(function () {
  'use strict';

  class ApiError extends Error {
    constructor(status, code, message, fields) { super(message); this.status = status; this.code = code; this.fields = fields || null; }
  }

  let csrfToken = null;
  const setCsrf = (t) => { csrfToken = t; };

  async function request(method, url, body) {
    const headers = { 'Accept': 'application/json', 'X-Requested-With': 'securenotes' };   // a cross-site page cannot send this header
    if (body !== undefined) headers['Content-Type'] = 'application/json';
    if (method !== 'GET' && csrfToken) headers['X-CSRF-Token'] = csrfToken;                // per-session secret

    let res;
    try {
      res = await fetch(url, { method, headers, credentials: 'same-origin', cache: 'no-store', body: body === undefined ? undefined : JSON.stringify(body) });
    } catch (e) {
      throw new ApiError(0, 'NETWORK', 'Could not reach the server. Check your connection and try again.');
    }
    let data = null;
    try { data = await res.json(); } catch (e) { /* empty or non-JSON body */ }
    if (!res.ok) {
      const err = (data && data.error) || {};
      throw new ApiError(res.status, err.code || 'ERROR', err.message || 'Something went wrong (HTTP ' + res.status + ').', err.fields);
    }
    return data;
  }

  window.Api = {
    ApiError, setCsrf,
    get: (u) => request('GET', u),
    post: (u, b) => request('POST', u, b === undefined ? {} : b),
    put: (u, b) => request('PUT', u, b),
    del: (u) => request('DELETE', u)
  };
})();
