const express = require('express');
const path = require('path');
const bcrypt = require('bcryptjs');
const crypto = require('crypto');
const multer = require('multer');
const fs = require('fs');
const Datastore = require('nedb-promises');

const app = express();

// ─── DATABASE ─────────────────────────────────────────────────────────────────
const dbDir = process.env.DB_PATH || path.join(__dirname, 'data');
fs.mkdirSync(dbDir, { recursive: true });

const db = {
  users:    Datastore.create({ filename: path.join(dbDir, 'users.db'),    autoload: true }),
  sessions: Datastore.create({ filename: path.join(dbDir, 'sessions.db'), autoload: true }),
  items:    Datastore.create({ filename: path.join(dbDir, 'items.db'),    autoload: true }),
  outfits:  Datastore.create({ filename: path.join(dbDir, 'outfits.db'),  autoload: true }),
  wishlist: Datastore.create({ filename: path.join(dbDir, 'wishlist.db'), autoload: true }),
};

// Ensure unique index on username
db.users.ensureIndex({ fieldName: 'username', unique: true, sparse: false });

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

async function requireAuth(req, res, next) {
  const token = (req.headers.authorization || '').replace('Bearer ', '').trim();
  if (!token) return res.status(401).json({ error: 'Not authenticated' });
  const session = await db.sessions.findOne({ token, expires: { $gt: new Date() } });
  if (!session) return res.status(401).json({ error: 'Session expired' });
  req.userId = session.userId;
  req.token = token;
  next();
}

function newExpiry() {
  return new Date(Date.now() + 90 * 24 * 60 * 60 * 1000);
}

// ─── AUTH ─────────────────────────────────────────────────────────────────────
app.post('/api/auth/register', async (req, res) => {
  const { username, password } = req.body;
  if (!username?.trim() || !password) return res.status(400).json({ error: 'Username and password required' });
  if (username.trim().length < 3) return res.status(400).json({ error: 'Username must be at least 3 characters' });
  if (password.length < 6) return res.status(400).json({ error: 'Password must be at least 6 characters' });
  try {
    const hash = bcrypt.hashSync(password, 10);
    const user = await db.users.insert({ username: username.trim().toLowerCase(), displayName: username.trim(), password_hash: hash, created: new Date() });
    const token = crypto.randomBytes(32).toString('hex');
    await db.sessions.insert({ token, userId: user._id, expires: newExpiry() });
    res.json({ token, username: user.displayName });
  } catch (e) {
    if (e.errorType === 'uniqueViolated') return res.status(400).json({ error: 'That username is already taken' });
    console.error(e);
    res.status(500).json({ error: 'Server error' });
  }
});

app.post('/api/auth/login', async (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) return res.status(400).json({ error: 'Username and password required' });
  const user = await db.users.findOne({ username: username.trim().toLowerCase() });
  if (!user || !bcrypt.compareSync(password, user.password_hash))
    return res.status(401).json({ error: 'Incorrect username or password' });
  const token = crypto.randomBytes(32).toString('hex');
  await db.sessions.insert({ token, userId: user._id, expires: newExpiry() });
  res.json({ token, username: user.displayName });
});

app.post('/api/auth/logout', requireAuth, async (req, res) => {
  await db.sessions.remove({ token: req.token }, {});
  res.json({ ok: true });
});

app.get('/api/auth/me', requireAuth, async (req, res) => {
  const user = await db.users.findOne({ _id: req.userId });
  if (!user) return res.status(404).json({ error: 'User not found' });
  res.json({ id: user._id, username: user.displayName });
});

// ─── WARDROBE ITEMS ───────────────────────────────────────────────────────────
app.get('/api/items', requireAuth, async (req, res) => {
  const items = await db.items.find({ userId: req.userId }).sort({ added: -1 });
  res.json(items.map(i => ({ ...i, id: i._id })));
});

app.post('/api/items', requireAuth, async (req, res) => {
  const { id, name, cat, colour, tags, imgUrl } = req.body;
  if (!name || !cat) return res.status(400).json({ error: 'Missing fields' });
  const doc = await db.items.insert({ _id: id || undefined, userId: req.userId, name, cat, colour: colour || '', tags: tags || [], img_url: imgUrl || '', added: new Date() });
  res.json({ ok: true, id: doc._id });
});

app.delete('/api/items/:id', requireAuth, async (req, res) => {
  await db.items.remove({ _id: req.params.id, userId: req.userId }, {});
  res.json({ ok: true });
});

// Photo upload
app.post('/api/upload', requireAuth, upload.single('photo'), (req, res) => {
  if (!req.file) return res.status(400).json({ error: 'No file' });
  res.json({ url: `/uploads/${req.userId}/${req.file.filename}` });
});

// Import seed wardrobe
app.post('/api/import-seed', requireAuth, async (req, res) => {
  const count = await db.items.count({ userId: req.userId });
  if (count > 0) return res.status(400).json({ error: 'Wardrobe already has items' });
  const SEED = require('./seed-items.json');
  for (const item of SEED) {
    await db.items.insert({ userId: req.userId, name: item.name, cat: item.cat, colour: item.colour || '', tags: item.tags || [], img_url: item.imgUrl || '', added: new Date() });
  }
  res.json({ ok: true, count: SEED.length });
});

// ─── OUTFITS ──────────────────────────────────────────────────────────────────
app.get('/api/outfits', requireAuth, async (req, res) => {
  const outfits = await db.outfits.find({ userId: req.userId }).sort({ created_at: -1 });
  res.json(outfits.map(o => ({ ...o, id: o._id })));
});

app.post('/api/outfits', requireAuth, async (req, res) => {
  const { name, items } = req.body;
  if (!name || !items) return res.status(400).json({ error: 'Missing fields' });
  const doc = await db.outfits.insert({ userId: req.userId, name, items, created_at: new Date() });
  res.json({ ok: true, id: doc._id });
});

app.delete('/api/outfits/:id', requireAuth, async (req, res) => {
  await db.outfits.remove({ _id: req.params.id, userId: req.userId }, {});
  res.json({ ok: true });
});

// ─── WISHLIST ─────────────────────────────────────────────────────────────────
app.get('/api/wishlist', requireAuth, async (req, res) => {
  const items = await db.wishlist.find({ userId: req.userId }).sort({ added: -1 });
  res.json(items.map(i => ({ ...i, id: i._id })));
});

app.post('/api/wishlist', requireAuth, async (req, res) => {
  const { name, reason, priority } = req.body;
  if (!name) return res.status(400).json({ error: 'Missing name' });
  const doc = await db.wishlist.insert({ userId: req.userId, name, reason: reason || '', priority: priority || 'med', added: new Date() });
  res.json({ ok: true, id: doc._id });
});

app.delete('/api/wishlist/:id', requireAuth, async (req, res) => {
  await db.wishlist.remove({ _id: req.params.id, userId: req.userId }, {});
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
