require('dotenv').config();
const express = require('express');
const session = require('express-session');
const SQLiteStoreFactory = require('connect-sqlite3');
const bcrypt = require('bcryptjs');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const path = require('path');
const fs = require('fs');
const Database = require('better-sqlite3');

const app = express();
const PORT = Number(process.env.PORT || 3000);
const isProduction = process.env.NODE_ENV === 'production';
const dataDir = process.env.DATA_DIR || path.join(__dirname, 'data');
fs.mkdirSync(dataDir, { recursive: true });

const db = new Database(path.join(dataDir, 'gb-tour-hub.sqlite'));
db.pragma('journal_mode = WAL');
db.pragma('foreign_keys = ON');
db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    email TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    created_at TEXT NOT NULL DEFAULT (datetime('now'))
  );
  CREATE TABLE IF NOT EXISTS bookings (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    district TEXT NOT NULL,
    package_name TEXT NOT NULL,
    travel_date TEXT NOT NULL,
    travellers INTEGER NOT NULL CHECK(travellers BETWEEN 1 AND 20),
    price_per_person INTEGER NOT NULL,
    total_price INTEGER NOT NULL,
    notes TEXT NOT NULL DEFAULT '',
    status TEXT NOT NULL DEFAULT 'pending',
    created_at TEXT NOT NULL DEFAULT (datetime('now'))
  );
`);

const tours = [
  { id:'hunza', district:'Hunza', title:'Hunza Valley Explorer', days:5, price:38500, description:'Karimabad, Baltit Fort, Altit Fort, Attabad Lake and Passu viewpoints.', includes:['Shared transport','Guesthouse stay','Local trip coordinator'] },
  { id:'skardu', district:'Skardu', title:'Skardu & Shangrila Escape', days:5, price:42000, description:'Upper Kachura, Shangrila, Skardu viewpoints and local bazaar.', includes:['Shared transport','Guesthouse stay','Sightseeing plan'] },
  { id:'fairy', district:'Diamer', title:'Fairy Meadows Adventure', days:3, price:29500, description:'Mountain scenery and a guided plan for the Fairy Meadows route.', includes:['Route coordination','Local accommodation','Trip support'] },
  { id:'ghizer', district:'Ghizer', title:'Ghizer Lakes & Valleys', days:4, price:32000, description:'Riverside scenery, village stops and the beautiful Phander region.', includes:['Shared transport','Guesthouse stay','Sightseeing plan'] },
  { id:'astore', district:'Astore', title:'Astore & Rama Meadows', days:4, price:34000, description:'Alpine meadows, forest roads and dramatic mountain panoramas.', includes:['Shared transport','Guesthouse stay','Trip coordination'] },
  { id:'nagar', district:'Nagar', title:'Nagar Mountain Getaway', days:3, price:26500, description:'Hoper Glacier viewpoints, valley villages and Rakaposhi views.', includes:['Shared transport','Guesthouse stay','Local route plan'] },
  { id:'shigar', district:'Shigar', title:'Shigar Heritage Trail', days:3, price:28500, description:'Historic Shigar Fort, traditional architecture and mountain scenery.', includes:['Shared transport','Guesthouse stay','Sightseeing plan'] },
  { id:'ghanche', district:'Ghanche', title:'Khaplu & Ghanche Culture', days:4, price:36000, description:'Khaplu Palace, local culture, river valleys and peaceful landscapes.', includes:['Shared transport','Guesthouse stay','Trip coordination'] },
  { id:'kharmang', district:'Kharmang', title:'Kharmang Waterfall Route', days:3, price:30000, description:'A relaxed route through eastern Baltistan scenery and waterfall stops.', includes:['Shared transport','Guesthouse stay','Sightseeing plan'] },
  { id:'gilgit', district:'Gilgit', title:'Gilgit City & Kargah', days:2, price:16500, description:'Explore Gilgit city, local markets, nearby viewpoints and Kargah area.', includes:['Shared transport','One night stay','Local trip coordinator'] }
];

app.disable('x-powered-by');
app.use(helmet({ contentSecurityPolicy: false }));
app.use(express.json({ limit: '20kb' }));
app.use(express.urlencoded({ extended: false, limit: '20kb' }));
if (isProduction) app.set('trust proxy', 1);
const SQLiteStore = SQLiteStoreFactory(session);
app.use(session({
  store: new SQLiteStore({ db: 'sessions.sqlite', dir: dataDir, table: 'sessions' }),
  name: 'gbtour.sid',
  secret: process.env.SESSION_SECRET || (isProduction ? (() => { throw new Error('SESSION_SECRET must be set in production'); })() : 'local-development-secret-change-before-deploy'),
  resave: false,
  saveUninitialized: false,
  rolling: true,
  cookie: { httpOnly: true, sameSite: 'lax', secure: isProduction, maxAge: 1000 * 60 * 60 * 24 * 7 }
}));
app.get('/', (req, res) => res.sendFile(path.join(__dirname, 'index.html')));

const authLimiter = rateLimit({ windowMs: 15 * 60 * 1000, limit: 12, standardHeaders: 'draft-8', legacyHeaders: false, message: { error: 'Too many attempts. Please wait a little and try again.' } });
const bookingLimiter = rateLimit({ windowMs: 60 * 60 * 1000, limit: 20, standardHeaders: 'draft-8', legacyHeaders: false });
const emailPattern = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
const cleanText = (value, max = 200) => String(value || '').trim().slice(0, max);
const publicUser = user => ({ id: user.id, name: user.name, email: user.email, joinedAt: user.created_at });
function requireAuth(req, res, next) {
  if (!req.session.userId) return res.status(401).json({ error: 'Please sign in to continue.' });
  const user = db.prepare('SELECT id, name, email, created_at FROM users WHERE id = ?').get(req.session.userId);
  if (!user) { req.session.destroy(() => {}); return res.status(401).json({ error: 'Your session expired. Please sign in again.' }); }
  req.user = user;
  next();
}
function regenerateSession(req) {
  return new Promise((resolve, reject) => req.session.regenerate(err => err ? reject(err) : resolve()));
}
function saveSession(req) {
  return new Promise((resolve, reject) => req.session.save(err => err ? reject(err) : resolve()));
}

app.get('/api/health', (req, res) => res.json({ status: 'ok', service: 'GB Tour Hub API' }));
app.get('/api/tours', (req, res) => res.json({ currency: 'PKR', note: 'Indicative starting prices per person; final quote depends on dates, group size, transport and accommodation.', tours }));
app.get('/api/auth/me', (req, res) => {
  if (!req.session.userId) return res.json({ user: null });
  const user = db.prepare('SELECT id, name, email, created_at FROM users WHERE id = ?').get(req.session.userId);
  if (!user) return res.json({ user: null });
  res.json({ user: publicUser(user) });
});
app.post('/api/auth/signup', authLimiter, async (req, res, next) => {
  try {
    const name = cleanText(req.body.name, 80);
    const email = cleanText(req.body.email, 254).toLowerCase();
    const password = String(req.body.password || '');
    if (name.length < 2) return res.status(400).json({ error: 'Please enter your full name (at least 2 characters).' });
    if (!emailPattern.test(email)) return res.status(400).json({ error: 'Please enter a valid email address.' });
    if (password.length < 8 || password.length > 72) return res.status(400).json({ error: 'Password must be 8–72 characters long.' });
    if (db.prepare('SELECT id FROM users WHERE email = ?').get(email)) return res.status(409).json({ error: 'An account with this email already exists. Please sign in.' });
    const passwordHash = await bcrypt.hash(password, 12);
    const result = db.prepare('INSERT INTO users (name, email, password_hash) VALUES (?, ?, ?)').run(name, email, passwordHash);
    await regenerateSession(req);
    req.session.userId = Number(result.lastInsertRowid);
    await saveSession(req);
    const user = db.prepare('SELECT id, name, email, created_at FROM users WHERE id = ?').get(req.session.userId);
    res.status(201).json({ user: publicUser(user), message: 'Your account is ready.' });
  } catch (err) { if (err.code === 'SQLITE_CONSTRAINT_UNIQUE') return res.status(409).json({ error: 'An account with this email already exists.' }); next(err); }
});
app.post('/api/auth/login', authLimiter, async (req, res, next) => {
  try {
    const email = cleanText(req.body.email, 254).toLowerCase();
    const password = String(req.body.password || '');
    const user = db.prepare('SELECT * FROM users WHERE email = ?').get(email);
    if (!user || !(await bcrypt.compare(password, user.password_hash))) return res.status(401).json({ error: 'Email or password is incorrect.' });
    await regenerateSession(req);
    req.session.userId = user.id;
    await saveSession(req);
    res.json({ user: publicUser(user), message: 'Welcome back.' });
  } catch (err) { next(err); }
});
app.post('/api/auth/logout', (req, res) => {
  req.session.destroy(err => {
    if (err) return res.status(500).json({ error: 'Could not sign out. Please try again.' });
    res.clearCookie('gbtour.sid', { httpOnly: true, sameSite: 'lax', secure: isProduction });
    res.json({ message: 'You are signed out.' });
  });
});
app.get('/api/bookings', requireAuth, (req, res) => {
  const bookings = db.prepare('SELECT id, district, package_name AS packageName, travel_date AS travelDate, travellers, price_per_person AS pricePerPerson, total_price AS totalPrice, notes, status, created_at AS createdAt FROM bookings WHERE user_id = ? ORDER BY id DESC').all(req.user.id);
  res.json({ bookings });
});
app.post('/api/bookings', requireAuth, bookingLimiter, (req, res) => {
  const tour = tours.find(item => item.id === cleanText(req.body.tourId, 40));
  const date = cleanText(req.body.travelDate, 10);
  const travellers = Number(req.body.travellers);
  const notes = cleanText(req.body.notes, 800);
  if (!tour) return res.status(400).json({ error: 'Please select a valid tour package.' });
  if (!/^\d{4}-\d{2}-\d{2}$/.test(date) || Number.isNaN(Date.parse(date)) || date < new Date().toISOString().slice(0, 10)) return res.status(400).json({ error: 'Please select a valid future travel date.' });
  if (!Number.isInteger(travellers) || travellers < 1 || travellers > 20) return res.status(400).json({ error: 'Travellers must be between 1 and 20.' });
  const total = tour.price * travellers;
  const result = db.prepare('INSERT INTO bookings (user_id, district, package_name, travel_date, travellers, price_per_person, total_price, notes) VALUES (?, ?, ?, ?, ?, ?, ?, ?)').run(req.user.id, tour.district, tour.title, date, travellers, tour.price, total, notes);
  const booking = db.prepare('SELECT id, district, package_name AS packageName, travel_date AS travelDate, travellers, price_per_person AS pricePerPerson, total_price AS totalPrice, notes, status, created_at AS createdAt FROM bookings WHERE id = ?').get(result.lastInsertRowid);
  res.status(201).json({ booking, message: 'Trip request saved. Our team must confirm availability and final pricing before payment.' });
});
app.use('/api', (req, res) => res.status(404).json({ error: 'API route not found.' }));
app.use((err, req, res, next) => {
  console.error(err);
  res.status(500).json({ error: 'Something went wrong. Please try again later.' });
});
app.listen(PORT, () => console.log(`GB Tour Hub running on port ${PORT}`));
