const { DatabaseSync } = require('node:sqlite');
const path = require('path');
const fs = require('fs');

const dataDirectory = path.join(__dirname, '..', '..', 'data');
fs.mkdirSync(dataDirectory, { recursive: true });
const databasePath = process.env.TABLENOW_DB_PATH || path.join(dataDirectory, 'tablenow.sqlite');
fs.mkdirSync(path.dirname(databasePath), { recursive: true });
const db = new DatabaseSync(databasePath);
db.exec('PRAGMA foreign_keys = ON; PRAGMA journal_mode = WAL;');

db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    full_name TEXT NOT NULL,
    email TEXT NOT NULL UNIQUE COLLATE NOCASE,
    password_hash TEXT NOT NULL,
    role TEXT NOT NULL DEFAULT 'user' CHECK (role IN ('user', 'admin')),
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
  );
  CREATE TABLE IF NOT EXISTS sessions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    token_hash TEXT NOT NULL UNIQUE,
    expires_at TEXT NOT NULL,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
  );
  CREATE TABLE IF NOT EXISTS restaurants (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    cuisine TEXT NOT NULL,
    area TEXT NOT NULL,
    price_level TEXT NOT NULL CHECK (price_level IN ('$', '$$', '$$$')),
    description TEXT NOT NULL DEFAULT '',
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
  );
  CREATE TABLE IF NOT EXISTS bookings (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    restaurant_id INTEGER NOT NULL,
    booking_date TEXT NOT NULL,
    booking_time TEXT NOT NULL,
    guests INTEGER NOT NULL CHECK (guests BETWEEN 1 AND 20),
    status TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'cancelled', 'completed')),
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
    FOREIGN KEY (restaurant_id) REFERENCES restaurants(id) ON DELETE RESTRICT
  );
  CREATE INDEX IF NOT EXISTS idx_sessions_token ON sessions(token_hash);
`);

// Migrate the first laboratory version, whose booking status allowed only active/cancelled.
const bookingSchema = db.prepare("SELECT sql FROM sqlite_master WHERE type='table' AND name='bookings'").get()?.sql || '';
if (!bookingSchema.includes("'completed'")) {
  db.exec(`
    PRAGMA foreign_keys = OFF;
    BEGIN IMMEDIATE;
    ALTER TABLE bookings RENAME TO bookings_legacy;
    CREATE TABLE bookings (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id INTEGER NOT NULL,
      restaurant_id INTEGER NOT NULL,
      booking_date TEXT NOT NULL,
      booking_time TEXT NOT NULL,
      guests INTEGER NOT NULL CHECK (guests BETWEEN 1 AND 20),
      status TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'cancelled', 'completed')),
      created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
      FOREIGN KEY (restaurant_id) REFERENCES restaurants(id) ON DELETE RESTRICT
    );
    INSERT INTO bookings (id,user_id,restaurant_id,booking_date,booking_time,guests,status,created_at)
      SELECT id,user_id,restaurant_id,booking_date,booking_time,guests,status,created_at FROM bookings_legacy;
    DROP TABLE bookings_legacy;
    COMMIT;
    PRAGMA foreign_keys = ON;
  `);
}
db.exec('CREATE INDEX IF NOT EXISTS idx_bookings_user ON bookings(user_id); CREATE INDEX IF NOT EXISTS idx_bookings_restaurant ON bookings(restaurant_id);');

const count = db.prepare('SELECT COUNT(*) AS count FROM restaurants').get().count;
if (count === 0) {
  const insert = db.prepare('INSERT INTO restaurants (name,cuisine,area,price_level,description) VALUES (?,?,?,?,?)');
  insert.run('Verde Garden', 'Європейська', 'Центр', '$$', 'Сезонні інгредієнти, авторська подача та затишна атмосфера.');
  insert.run('Sora Sushi', 'Азійська', 'Печерськ', '$$$', 'Ресторан азійської кухні.');
  insert.run('Casa Mia', 'Італійська', 'Поділ', '$$', 'Ресторан італійської кухні.');
  insert.run('Дім Смаку', 'Українська', 'Центр', '$', 'Ресторан української кухні.');
}

module.exports = { db };
