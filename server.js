const express = require('express');
const path = require('path');
const Database = require('better-sqlite3');
const bcrypt = require('bcryptjs');
const crypto = require('crypto');
const multer = require('multer');
const fs = require('fs');

const app = express();
const db = new Database(path.join(__dirname, 'wardrobe.db'));
db.pragma('journal_mode = WAL');

// ─── SCHEMA ──────────────────────────────────────────────────────────────────
db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL COLLATE NOCASE,
    password_hash TEXT NOT NULL,
    created_at TEXT DEFAULT (datetime('now'))
  );

  CREATE TABLE IF NOT EXISTS sessions (
    token TEXT PRIMARY KEY,
    user_id INTEGER NOT NULL,
    expires_at TEXT NOT NULL
  );

  CREATE TABLE IF NOT EXISTS wardrobe_items (
    id TEXT PRIMARY KEY,
    user_id INTEGER NOT NULL,
    name TEXT NOT NULL,
    cat TEXT NOT NULL,
    colour TEXT DEFAULT '',
    tags TEXT DEFAULT '[]',
    img_url TEXT DEFAULT '',
    added TEXT DEFAULT (datetime('now')),
    FOREIGN KEY (user_id) REFERENCES users(id)
  );

  CREATE TABLE IF NOT EXISTS outfits (
    id TEXT PRIMARY KEY,
    user_id INTEGER NOT NULL,
    name TEXT NOT NULL,
    items TEXT NOT NULL,
    created_at TEXT DEFAULT (datetime('now')),
    FOREIGN KEY (user_id) REFERENCES users(id)
  );

  CREATE TABLE IF NOT EXISTS wishlist (
    id TEXT PRIMARY KEY,
    user_id INTEGER NOT NULL,
    name TEXT NOT NULL,
    reason TEXT DEFAULT '',
    priority TEXT DEFAULT 'med',
    added TEXT DEFAULT (datetime('now')),
    FOREIGN KEY (user_id) REFERENCES users(id)
  );
`);

// ─── MIDDLEWARE ───────────────────────────────────────────────────────────────
app.use(express.json({ limit: '20mb' }));
app.use(express.static(path.join(__dirname, 'public')));

// Multer — save uploaded photos per user
const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    const dir = path.join(__dirname, 'public', 'uploads', String(req.userId));
    fs.mkdirSync(dir, { recursive: true });
    cb(null, dir);
  },
  filename: (req, file, cb) => {
    const ext = path.extname(file.originalname) || '.jpg';
    cb(null, Date.now() + '_' + crypto.randomBytes(4).toString('hex') + ext);
  }
});
const upload = multer({ storage, limits: { fileSize: 15 * 1024 * 1024 } });

function requireAuth(req, res, next) {
  const token = (req.headers.authorization || '').replace('Bearer ', '').trim();
  if (!token) return res.status(401).json({ error: 'Not authenticated' });
  const session = db.prepare(
    `SELECT * FROM sessions WHERE token = ? AND expires_at > datetime('now')`
  ).get(token);
  if (!session) return res.status(401).json({ error: 'Session expired' });
  req.userId = session.user_id;
  req.token = token;
  next();
}

// ─── AUTH ─────────────────────────────────────────────────────────────────────
app.post('/api/auth/register', (req, res) => {
  const { username, password } = req.body;
  if (!username?.trim() || !password) return res.status(400).json({ error: 'Username and password required' });
  if (username.trim().length < 3) return res.status(400).json({ error: 'Username must be at least 3 characters' });
  if (password.length < 6) return res.status(400).json({ error: 'Password must be at least 6 characters' });
  try {
    const hash = bcrypt.hashSync(password, 10);
    const result = db.prepare('INSERT INTO users (username, password_hash) VALUES (?, ?)').run(username.trim(), hash);
    const token = crypto.randomBytes(32).toString('hex');
    const expires = new Date(Date.now() + 90 * 24 * 60 * 60 * 1000).toISOString();
    db.prepare('INSERT INTO sessions (token, user_id, expires_at) VALUES (?, ?, ?)').run(token, result.lastInsertRowid, expires);
    res.json({ token, username: username.trim() });
  } catch (e) {
    if (e.message.includes('UNIQUE')) return res.status(400).json({ error: 'That username is already taken' });
    res.status(500).json({ error: 'Server error' });
  }
});

app.post('/api/auth/login', (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) return res.status(400).json({ error: 'Username and password required' });
  const user = db.prepare('SELECT * FROM users WHERE username = ?').get(username.trim());
  if (!user || !bcrypt.compareSync(password, user.password_hash))
    return res.status(401).json({ error: 'Incorrect username or password' });
  const token = crypto.randomBytes(32).toString('hex');
  const expires = new Date(Date.now() + 90 * 24 * 60 * 60 * 1000).toISOString();
  db.prepare('INSERT INTO sessions (token, user_id, expires_at) VALUES (?, ?, ?)').run(token, user.id, expires);
  res.json({ token, username: user.username });
});

app.post('/api/auth/logout', requireAuth, (req, res) => {
  db.prepare('DELETE FROM sessions WHERE token = ?').run(req.token);
  res.json({ ok: true });
});

app.get('/api/auth/me', requireAuth, (req, res) => {
  const user = db.prepare('SELECT id, username FROM users WHERE id = ?').get(req.userId);
  res.json(user);
});

// ─── WARDROBE ITEMS ───────────────────────────────────────────────────────────
app.get('/api/items', requireAuth, (req, res) => {
  const rows = db.prepare('SELECT * FROM wardrobe_items WHERE user_id = ? ORDER BY added DESC').all(req.userId);
  res.json(rows.map(r => ({ ...r, tags: JSON.parse(r.tags) })));
});

app.post('/api/items', requireAuth, (req, res) => {
  const { id, name, cat, colour, tags, imgUrl } = req.body;
  if (!id || !name || !cat) return res.status(400).json({ error: 'Missing fields' });
  db.prepare(
    'INSERT INTO wardrobe_items (id, user_id, name, cat, colour, tags, img_url) VALUES (?, ?, ?, ?, ?, ?, ?)'
  ).run(id, req.userId, name, cat, colour || '', JSON.stringify(tags || []), imgUrl || '');
  res.json({ ok: true });
});

app.put('/api/items/:id', requireAuth, (req, res) => {
  const { name, cat, colour, tags } = req.body;
  db.prepare(
    'UPDATE wardrobe_items SET name=?, cat=?, colour=?, tags=? WHERE id=? AND user_id=?'
  ).run(name, cat, colour || '', JSON.stringify(tags || []), req.params.id, req.userId);
  res.json({ ok: true });
});

app.delete('/api/items/:id', requireAuth, (req, res) => {
  db.prepare('DELETE FROM wardrobe_items WHERE id = ? AND user_id = ?').run(req.params.id, req.userId);
  res.json({ ok: true });
});

// Photo upload
app.post('/api/upload', requireAuth, upload.single('photo'), (req, res) => {
  if (!req.file) return res.status(400).json({ error: 'No file' });
  const url = `/uploads/${req.userId}/${req.file.filename}`;
  res.json({ url });
});

// Import Avril's seed wardrobe (only if user has 0 items)
app.post('/api/import-seed', requireAuth, (req, res) => {
  const count = db.prepare('SELECT COUNT(*) as n FROM wardrobe_items WHERE user_id = ?').get(req.userId).n;
  if (count > 0) return res.status(400).json({ error: 'Wardrobe already has items' });
  const SEED = require('./seed-items.json');
  const insert = db.prepare(
    'INSERT INTO wardrobe_items (id, user_id, name, cat, colour, tags, img_url) VALUES (?, ?, ?, ?, ?, ?, ?)'
  );
  const insertMany = db.transaction((items) => {
    for (const item of items) {
      insert.run(item.id + '_' + req.userId, req.userId, item.name, item.cat, item.colour || '', JSON.stringify(item.tags || []), item.imgUrl || '');
    }
  });
  insertMany(SEED);
  res.json({ ok: true, count: SEED.length });
});

// ─── OUTFITS ──────────────────────────────────────────────────────────────────
app.get('/api/outfits', requireAuth, (req, res) => {
  const rows = db.prepare('SELECT * FROM outfits WHERE user_id = ? ORDER BY created_at DESC').all(req.userId);
  res.json(rows.map(r => ({ ...r, items: JSON.parse(r.items) })));
});

app.post('/api/outfits', requireAuth, (req, res) => {
  const { id, name, items } = req.body;
  if (!id || !name || !items) return res.status(400).json({ error: 'Missing fields' });
  db.prepare('INSERT INTO outfits (id, user_id, name, items) VALUES (?, ?, ?, ?)').run(id, req.userId, name, JSON.stringify(items));
  res.json({ ok: true });
});

app.delete('/api/outfits/:id', requireAuth, (req, res) => {
  db.prepare('DELETE FROM outfits WHERE id = ? AND user_id = ?').run(req.params.id, req.userId);
  res.json({ ok: true });
});

// ─── WISHLIST ─────────────────────────────────────────────────────────────────
app.get('/api/wishlist', requireAuth, (req, res) => {
  res.json(db.prepare('SELECT * FROM wishlist WHERE user_id = ? ORDER BY added DESC').all(req.userId));
});

app.post('/api/wishlist', requireAuth, (req, res) => {
  const { id, name, reason, priority } = req.body;
  if (!id || !name) return res.status(400).json({ error: 'Missing fields' });
  db.prepare('INSERT INTO wishlist (id, user_id, name, reason, priority) VALUES (?, ?, ?, ?, ?)').run(id, req.userId, name, reason || '', priority || 'med');
  res.json({ ok: true });
});

app.delete('/api/wishlist/:id', requireAuth, (req, res) => {
  db.prepare('DELETE FROM wishlist WHERE id = ? AND user_id = ?').run(req.params.id, req.userId);
  res.json({ ok: true });
});

// ─── CATCH-ALL ────────────────────────────────────────────────────────────────
app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'wardrobe.html'));
});

const PORT = process.env.PORT || 3001;
app.listen(PORT, () => {
  console.log(`\n✦ Style Studio running at http://localhost:${PORT}`);
  console.log(`   Press Ctrl+C to stop.\n`);
});
