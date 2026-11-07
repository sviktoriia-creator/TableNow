const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');

const temporaryDirectory = fs.mkdtempSync(path.join(os.tmpdir(), 'tablenow-test-'));
process.env.TABLENOW_DB_PATH = path.join(temporaryDirectory, 'test.sqlite');
const { db } = require('../src/db/database');

test('база даних створює початкові ресторани', () => {
  const rows = db.prepare('SELECT name FROM restaurants ORDER BY id').all();
  assert.equal(rows.length, 4);
  assert.equal(rows[0].name, 'Verde Garden');
});

test('користувач може створити бронювання, а зовнішні ключі перевіряються', () => {
  const user = db.prepare('INSERT INTO users(full_name,email,password_hash) VALUES(?,?,?)').run('Тестовий Користувач', 'test@example.com', 'test-hash');
  const booking = db.prepare('INSERT INTO bookings(user_id,restaurant_id,booking_date,booking_time,guests) VALUES(?,?,?,?,?)').run(user.lastInsertRowid, 1, '2030-01-01', '18:30', 2);
  const row = db.prepare('SELECT bookings.id, restaurants.name AS restaurant FROM bookings JOIN restaurants ON restaurants.id=bookings.restaurant_id WHERE bookings.id=?').get(booking.lastInsertRowid);
  assert.equal(row.restaurant, 'Verde Garden');
  assert.throws(() => db.prepare('INSERT INTO bookings(user_id,restaurant_id,booking_date,booking_time,guests) VALUES(?,?,?,?,?)').run(user.lastInsertRowid, 99999, '2030-01-01', '18:30', 2));
});

test('база даних не дозволяє некоректну кількість гостей', () => {
  const user = db.prepare('SELECT id FROM users WHERE email=?').get('test@example.com');
  assert.throws(() => db.prepare('INSERT INTO bookings(user_id,restaurant_id,booking_date,booking_time,guests) VALUES(?,?,?,?,?)').run(user.id, 1, '2030-01-01', '18:30', 0));
});

test('статус бронювання можна змінити на скасований', () => {
  const user = db.prepare('SELECT id FROM users WHERE email=?').get('test@example.com');
  const result = db.prepare('INSERT INTO bookings(user_id,restaurant_id,booking_date,booking_time,guests) VALUES(?,?,?,?,?)').run(user.id, 1, '2030-01-01', '19:00', 3);
  db.prepare("UPDATE bookings SET status='cancelled' WHERE id=?").run(result.lastInsertRowid);
  assert.equal(db.prepare('SELECT status FROM bookings WHERE id=?').get(result.lastInsertRowid).status, 'cancelled');
});

test.after(() => {
  db.close();
  fs.rmSync(temporaryDirectory, { recursive: true, force: true });
});
