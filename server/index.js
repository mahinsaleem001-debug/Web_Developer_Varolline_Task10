const { createApp } = require('./app');

const production = process.env.NODE_ENV === 'production';
const port = Number(process.env.PORT) || 3000;
const { app, close } = createApp({
  dbFile: process.env.DB_FILE || 'data/securenotes.db',
  bcryptCost: Number(process.env.BCRYPT_COST) || 12,
  production,
  trustProxy: process.env.TRUST_PROXY === '1'
});

const server = app.listen(port, () => console.log('SecureNotes running on http://localhost:' + port + (production ? ' (production mode)' : '')));

function shutdown() { server.close(() => { close(); process.exit(0); }); setTimeout(() => process.exit(0), 3000).unref(); }
process.on('SIGINT', shutdown);
process.on('SIGTERM', shutdown);
