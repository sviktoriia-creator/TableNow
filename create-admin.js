const fs = require('fs');
const path = require('path');
const envFile = path.join(__dirname, '.env');
if (fs.existsSync(envFile)) {
  for (const line of fs.readFileSync(envFile, 'utf8').split(/\r?\n/)) {
    const match = line.match(/^\s*([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.*)\s*$/);
    if (match && !process.env[match[1]]) process.env[match[1]] = match[2].replace(/^['"]|['"]$/g, '');
  }
}
const crypto = require('crypto');
const { db } = require('./src/db/database');
const email = (process.argv[2] || process.env.ADMIN_EMAIL || '').trim().toLowerCase();
const password = process.argv[3] || process.env.ADMIN_PASSWORD || '';
const fullName = process.env.ADMIN_NAME || 'TableNow Administrator';
if (!email || !/^\S+@\S+\.\S+$/.test(email) || password.length < 12) {
  console.error('Використання: npm run create-admin -- admin@example.com "StrongPassword123!"');
  console.error('Пароль адміністратора має містити щонайменше 12 символів.');
  process.exit(1);
}
const salt = crypto.randomBytes(16);
const hash = crypto.scryptSync(password, salt, 64);
const passwordHash = `${salt.toString('hex')}:${hash.toString('hex')}`;
const existing = db.prepare('SELECT id FROM users WHERE email=?').get(email);
if (existing) {
  db.prepare("UPDATE users SET full_name=?, password_hash=?, role='admin' WHERE id=?").run(fullName, passwordHash, existing.id);
  console.log(`Права адміністратора оновлено для ${email}`);
} else {
  db.prepare("INSERT INTO users (full_name,email,password_hash,role) VALUES (?,?,?,'admin')").run(fullName, email, passwordHash);
  console.log(`Адміністратора створено: ${email}`);
}
