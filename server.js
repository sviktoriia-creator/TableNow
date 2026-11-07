const fs = require('fs');
const path = require('path');
const envFile = path.join(__dirname, '.env');
if (fs.existsSync(envFile)) {
  for (const line of fs.readFileSync(envFile, 'utf8').split(/\r?\n/)) {
    const match = line.match(/^\s*([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.*)\s*$/);
    if (match && !process.env[match[1]]) process.env[match[1]] = match[2].replace(/^['"]|['"]$/g, '');
  }
}
const express = require('express');
const helmet = require('helmet');
const crypto = require('crypto');
const { db } = require('./src/db/database');

const app = express();
const PORT = Number(process.env.PORT) || 3000;
const SESSION_COOKIE = 'tablenow_session';
const SESSION_DAYS = 7;

app.disable('x-powered-by');
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      ...helmet.contentSecurityPolicy.getDefaultDirectives(),
      "script-src": ["'self'"],
      "style-src": ["'self'", "'unsafe-inline'"],
      "img-src": ["'self'", 'data:'],
    },
  },
}));
app.use(express.json({ limit: '50kb', strict: true }));

function parseCookies(req) {
  const header = req.headers.cookie || '';
  const cookies = {};
  for (const part of header.split(';')) {
    const trimmed = part.trim();
    const index = trimmed.indexOf('=');
    if (index < 0) continue;
    try { cookies[trimmed.slice(0, index)] = decodeURIComponent(trimmed.slice(index + 1)); } catch { /* Ignore malformed cookie values. */ }
  }
  return cookies;
}
function setSessionCookie(res, token) {
  const secure = process.env.NODE_ENV === 'production' ? '; Secure' : '';
  res.setHeader('Set-Cookie', `${SESSION_COOKIE}=${encodeURIComponent(token)}; HttpOnly; SameSite=Strict; Path=/; Max-Age=${SESSION_DAYS * 86400}${secure}`);
}
function clearSessionCookie(res) {
  const secure = process.env.NODE_ENV === 'production' ? '; Secure' : '';
  res.setHeader('Set-Cookie', `${SESSION_COOKIE}=; HttpOnly; SameSite=Strict; Path=/; Max-Age=0${secure}`);
}
function tokenHash(token) { return crypto.createHash('sha256').update(token).digest('hex'); }
function currentUser(req) {
  const token = parseCookies(req)[SESSION_COOKIE];
  if (!token || token.length < 40 || token.length > 100) return null;
  return db.prepare(`
    SELECT users.id, users.full_name, users.email, users.role
    FROM sessions JOIN users ON users.id = sessions.user_id
    WHERE sessions.token_hash = ? AND sessions.expires_at > datetime('now')
  `).get(tokenHash(token)) || null;
}
function requireAuth(req, res, next) {
  const user = currentUser(req);
  if (!user) return res.status(401).json({ error: 'Потрібно увійти в акаунт.' });
  req.user = user;
  next();
}
function requireAdmin(req, res, next) {
  if (req.user.role !== 'admin') return res.status(403).json({ error: 'Недостатньо прав доступу.' });
  next();
}
function cleanText(value, max = 120) {
  return typeof value === 'string' ? value.trim().slice(0, max) : '';
}
function validEmail(email) { return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email) && email.length <= 254; }
function localDateString() {
  const now = new Date();
  return `${now.getFullYear()}-${String(now.getMonth() + 1).padStart(2, '0')}-${String(now.getDate()).padStart(2, '0')}`;
}
function validDateString(value) {
  if (!/^\d{4}-\d{2}-\d{2}$/.test(value)) return false;
  const date = new Date(`${value}T00:00:00.000Z`);
  return Number.isFinite(date.getTime()) && date.toISOString().slice(0, 10) === value;
}
function passwordHash(password) {
  const salt = crypto.randomBytes(16);
  const derived = crypto.scryptSync(password, salt, 64);
  return `${salt.toString('hex')}:${derived.toString('hex')}`;
}
function ensureAdminFromEnvironment() {
  const email = cleanText(process.env.ADMIN_EMAIL, 254).toLowerCase();
  const password = process.env.ADMIN_PASSWORD || '';
  if (!email || !validEmail(email) || password.length < 12) return;
  const existing = db.prepare('SELECT id FROM users WHERE email = ?').get(email);
  if (!existing) {
    const name = cleanText(process.env.ADMIN_NAME || 'TableNow Administrator', 100);
    db.prepare("INSERT INTO users (full_name, email, password_hash, role) VALUES (?, ?, ?, 'admin')")
      .run(name, email, passwordHash(password));
    console.log(`Адміністратора створено з ADMIN_EMAIL: ${email}`);
  }
}
function verifyPassword(password, stored) {
  try {
    const [saltHex, hashHex] = stored.split(':');
    const expected = Buffer.from(hashHex, 'hex');
    const actual = crypto.scryptSync(password, Buffer.from(saltHex, 'hex'), 64);
    return expected.length === actual.length && crypto.timingSafeEqual(expected, actual);
  } catch { return false; }
}

ensureAdminFromEnvironment();

// Simple in-memory rate limit for authentication attempts.
const authAttempts = new Map();
function authRateLimit(req, res, next) {
  const key = req.ip;
  const now = Date.now();
  const record = authAttempts.get(key) || { count: 0, resetAt: now + 15 * 60 * 1000 };
  if (now > record.resetAt) { record.count = 0; record.resetAt = now + 15 * 60 * 1000; }
  record.count += 1;
  authAttempts.set(key, record);
  if (record.count > 30) return res.status(429).json({ error: 'Забагато спроб. Спробуйте пізніше.' });
  next();
}

app.get('/api/health', (req, res) => res.json({ status: 'ok', application: 'TableNow', database: 'SQLite' }));

// Authentication
app.post('/api/auth/register', authRateLimit, (req, res) => {
  const fullName = cleanText(req.body?.fullName, 100);
  const email = cleanText(req.body?.email, 254).toLowerCase();
  const password = typeof req.body?.password === 'string' ? req.body.password : '';
  if (fullName.length < 2) return res.status(400).json({ error: 'Вкажіть ім’я (не менше 2 символів).' });
  if (!validEmail(email)) return res.status(400).json({ error: 'Вкажіть коректну email-адресу.' });
  if (password.length < 8 || password.length > 128) return res.status(400).json({ error: 'Пароль має містити від 8 до 128 символів.' });
  try {
    const result = db.prepare('INSERT INTO users (full_name, email, password_hash) VALUES (?, ?, ?)').run(fullName, email, passwordHash(password));
    const user = db.prepare('SELECT id, full_name, email, role FROM users WHERE id = ?').get(result.lastInsertRowid);
    const token = crypto.randomBytes(32).toString('hex');
    db.prepare("INSERT INTO sessions (user_id, token_hash, expires_at) VALUES (?, ?, datetime('now', '+7 days'))").run(user.id, tokenHash(token));
    setSessionCookie(res, token);
    res.status(201).json({ user });
  } catch (error) {
    if (String(error.code).includes('SQLITE_CONSTRAINT_UNIQUE')) return res.status(409).json({ error: 'Акаунт із такою email-адресою вже існує.' });
    console.error('Register error:', error.message);
    res.status(500).json({ error: 'Не вдалося створити акаунт.' });
  }
});

app.post('/api/auth/login', authRateLimit, (req, res) => {
  const email = cleanText(req.body?.email, 254).toLowerCase();
  const password = typeof req.body?.password === 'string' ? req.body.password : '';
  const row = db.prepare('SELECT * FROM users WHERE email = ?').get(email);
  if (!row || !verifyPassword(password, row.password_hash)) return res.status(401).json({ error: 'Неправильна email-адреса або пароль.' });
  const token = crypto.randomBytes(32).toString('hex');
  db.prepare("INSERT INTO sessions (user_id, token_hash, expires_at) VALUES (?, ?, datetime('now', '+7 days'))").run(row.id, tokenHash(token));
  setSessionCookie(res, token);
  res.json({ user: { id: row.id, full_name: row.full_name, email: row.email, role: row.role } });
});

app.post('/api/auth/logout', (req, res) => {
  const token = parseCookies(req)[SESSION_COOKIE];
  if (token) db.prepare('DELETE FROM sessions WHERE token_hash = ?').run(tokenHash(token));
  clearSessionCookie(res);
  res.json({ message: 'Ви вийшли з акаунта.' });
});
app.get('/api/auth/me', (req, res) => res.json({ user: currentUser(req) }));

// Restaurants: public read, administrator-only write.
app.get('/api/restaurants', (req, res) => {
  const q = cleanText(req.query.q, 100);
  const cuisine = cleanText(req.query.cuisine, 50);
  const area = cleanText(req.query.area, 50);
  const price = cleanText(req.query.price, 3);
  const rows = db.prepare(`
    SELECT id, name, cuisine, area, price_level, description, created_at
    FROM restaurants
    WHERE (? = '' OR name LIKE '%' || ? || '%' OR cuisine LIKE '%' || ? || '%')
      AND (? = '' OR cuisine = ?) AND (? = '' OR area = ?) AND (? = '' OR price_level = ?)
    ORDER BY id DESC
  `).all(q, q, q, cuisine, cuisine, area, area, price, price);
  res.json({ data: rows });
});
app.get('/api/restaurants/:id', (req, res) => {
  const restaurant = db.prepare('SELECT id, name, cuisine, area, price_level, description, created_at FROM restaurants WHERE id = ?').get(Number(req.params.id));
  if (!restaurant) return res.status(404).json({ error: 'Ресторан не знайдено.' });
  res.json({ data: restaurant });
});
app.post('/api/restaurants', requireAuth, requireAdmin, (req, res) => {
  const name = cleanText(req.body?.name, 100);
  const cuisine = cleanText(req.body?.cuisine, 50);
  const area = cleanText(req.body?.area, 50);
  const price = cleanText(req.body?.priceLevel, 3);
  const description = cleanText(req.body?.description, 500);
  if (!name || !cuisine || !area || !['$', '$$', '$$$'].includes(price)) return res.status(400).json({ error: 'Перевірте назву, кухню, район і цінову категорію.' });
  const result = db.prepare('INSERT INTO restaurants (name, cuisine, area, price_level, description) VALUES (?, ?, ?, ?, ?)').run(name, cuisine, area, price, description);
  const data = db.prepare('SELECT id, name, cuisine, area, price_level, description, created_at FROM restaurants WHERE id = ?').get(result.lastInsertRowid);
  res.status(201).json({ data });
});
app.put('/api/restaurants/:id', requireAuth, requireAdmin, (req, res) => {
  const id = Number(req.params.id);
  const existing = db.prepare('SELECT id FROM restaurants WHERE id = ?').get(id);
  if (!existing) return res.status(404).json({ error: 'Ресторан не знайдено.' });
  const name = cleanText(req.body?.name, 100);
  const cuisine = cleanText(req.body?.cuisine, 50);
  const area = cleanText(req.body?.area, 50);
  const price = cleanText(req.body?.priceLevel, 3);
  const description = cleanText(req.body?.description, 500);
  if (!name || !cuisine || !area || !['$', '$$', '$$$'].includes(price)) return res.status(400).json({ error: 'Перевірте поля ресторану.' });
  db.prepare('UPDATE restaurants SET name=?, cuisine=?, area=?, price_level=?, description=? WHERE id=?').run(name, cuisine, area, price, description, id);
  res.json({ data: db.prepare('SELECT id, name, cuisine, area, price_level, description FROM restaurants WHERE id=?').get(id) });
});
app.delete('/api/restaurants/:id', requireAuth, requireAdmin, (req, res) => {
  try {
    const result = db.prepare('DELETE FROM restaurants WHERE id = ?').run(Number(req.params.id));
    if (!result.changes) return res.status(404).json({ error: 'Ресторан не знайдено.' });
    res.json({ message: 'Ресторан видалено.' });
  } catch (error) {
    if (String(error.code).includes('SQLITE_CONSTRAINT_FOREIGNKEY')) return res.status(409).json({ error: 'Не можна видалити ресторан, для якого вже існують бронювання.' });
    throw error;
  }
});

// Bookings: users can access only their own records; admins can view all.
app.get('/api/bookings', requireAuth, (req, res) => {
  db.prepare("UPDATE bookings SET status='completed' WHERE status='active' AND booking_date < date('now', 'localtime')").run();
  const rows = req.user.role === 'admin'
    ? db.prepare(`SELECT b.id, b.booking_date, b.booking_time, b.guests, b.status, b.created_at, r.name AS restaurant, u.full_name AS customer_name, u.email AS customer_email FROM bookings b JOIN restaurants r ON r.id=b.restaurant_id JOIN users u ON u.id=b.user_id ORDER BY b.booking_date DESC, b.booking_time DESC`).all()
    : db.prepare(`SELECT b.id, b.booking_date, b.booking_time, b.guests, b.status, b.created_at, r.name AS restaurant, u.full_name AS customer_name, u.email AS customer_email FROM bookings b JOIN restaurants r ON r.id=b.restaurant_id JOIN users u ON u.id=b.user_id WHERE b.user_id=? ORDER BY b.booking_date DESC, b.booking_time DESC`).all(req.user.id);
  res.json({ data: rows });
});
app.post('/api/bookings', requireAuth, (req, res) => {
  const restaurantId = Number(req.body?.restaurantId);
  const date = cleanText(req.body?.date, 10);
  const time = cleanText(req.body?.time, 5);
  const guests = Number(req.body?.guests);
  const dateValid = validDateString(date);
  if (!db.prepare('SELECT id FROM restaurants WHERE id=?').get(restaurantId)) return res.status(404).json({ error: 'Ресторан не знайдено.' });
  if (!dateValid || date < localDateString()) return res.status(400).json({ error: 'Дата бронювання не може бути в минулому.' });
  if (!/^([01]\d|2[0-3]):[0-5]\d$/.test(time)) return res.status(400).json({ error: 'Вкажіть коректний час.' });
  if (!Number.isInteger(guests) || guests < 1 || guests > 20) return res.status(400).json({ error: 'Кількість гостей має бути від 1 до 20.' });
  const result = db.prepare('INSERT INTO bookings (user_id, restaurant_id, booking_date, booking_time, guests) VALUES (?, ?, ?, ?, ?)').run(req.user.id, restaurantId, date, time, guests);
  const data = db.prepare(`SELECT b.id, b.booking_date, b.booking_time, b.guests, b.status, r.name AS restaurant FROM bookings b JOIN restaurants r ON r.id=b.restaurant_id WHERE b.id=?`).get(result.lastInsertRowid);
  res.status(201).json({ data });
});
app.put('/api/bookings/:id', requireAuth, (req, res) => {
  const id = Number(req.params.id);
  const booking = db.prepare('SELECT * FROM bookings WHERE id=?').get(id);
  if (!booking) return res.status(404).json({ error: 'Бронювання не знайдено.' });
  if (booking.user_id !== req.user.id && req.user.role !== 'admin') return res.status(403).json({ error: 'Немає доступу до цього бронювання.' });
  if (booking.status !== 'active') return res.status(409).json({ error: 'Це бронювання вже не можна змінити.' });
  const date = cleanText(req.body?.date, 10);
  const time = cleanText(req.body?.time, 5);
  const guests = Number(req.body?.guests);
  if (!validDateString(date) || date < localDateString() || !/^([01]\d|2[0-3]):[0-5]\d$/.test(time) || !Number.isInteger(guests) || guests < 1 || guests > 20) return res.status(400).json({ error: 'Перевірте дату, час і кількість гостей.' });
  db.prepare('UPDATE bookings SET booking_date=?, booking_time=?, guests=? WHERE id=?').run(date, time, guests, id);
  res.json({ message: 'Бронювання оновлено.' });
});
app.delete('/api/bookings/:id', requireAuth, (req, res) => {
  const id = Number(req.params.id);
  const booking = db.prepare('SELECT * FROM bookings WHERE id=?').get(id);
  if (!booking) return res.status(404).json({ error: 'Бронювання не знайдено.' });
  if (booking.user_id !== req.user.id && req.user.role !== 'admin') return res.status(403).json({ error: 'Немає доступу до цього бронювання.' });
  if (booking.status !== 'active') return res.status(409).json({ error: 'Це бронювання вже не можна скасувати.' });
  db.prepare("UPDATE bookings SET status='cancelled' WHERE id=?").run(id);
  res.json({ message: 'Бронювання скасовано.' });
});

app.use(express.static(path.join(__dirname, 'public')));
app.use('/api', (req, res) => res.status(404).json({ error: 'API-маршрут не знайдено.' }));
app.use((error, req, res, next) => {
  console.error(error);
  if (res.headersSent) return next(error);
  res.status(400).json({ error: 'Некоректний запит.' });
});

app.listen(PORT, () => console.log(`TableNow запущено: http://localhost:${PORT}`));
