// server.js
require('dotenv').config();
const express = require('express');
const bodyParser = require('body-parser');
const sqlite3 = require('sqlite3');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const cookieParser = require('cookie-parser');
const nodemailer = require('nodemailer');
const speakeasy = require('speakeasy');
const qrcode = require('qrcode');
const { v4: uuidv4 } = require('uuid');
const path = require('path');

const app = express();
const DB_FILE = './data.sqlite';
const db = new sqlite3.Database(DB_FILE);

const JWT_SECRET = process.env.JWT_SECRET || 'devsecret';
const APP_BASE_URL = process.env.APP_BASE_URL || 'http://localhost:3000';

// init tables
db.serialize(() => {
  db.run(`CREATE TABLE IF NOT EXISTS users (
    id TEXT PRIMARY KEY,
    email TEXT UNIQUE,
    username TEXT UNIQUE,
    password_hash TEXT,
    balance REAL DEFAULT 0,
    twofa_secret TEXT,
    twofa_enabled INTEGER DEFAULT 0,
    reset_token TEXT
  )`);

  db.run(`CREATE TABLE IF NOT EXISTS transactions (
    id TEXT PRIMARY KEY,
    from_user_id TEXT,
    to_user_id TEXT,
    amount REAL,
    memo TEXT,
    created_at TEXT
  )`);
});

app.use(bodyParser.json());
app.use(cookieParser());
app.use(express.static(path.join(__dirname, 'public')));

// nodemailer setup
const transporter = nodemailer.createTransport({
  host: process.env.SMTP_HOST,
  port: process.env.SMTP_PORT || 587,
  secure: false,
  auth: {
    user: process.env.SMTP_USER,
    pass: process.env.SMTP_PASS
  }
});

// helper
function sendJSON(res, data = {}) {
  res.json(data);
}

function authMiddleware(req, res, next) {
  const token = req.cookies['token'];
  if (!token) return res.status(401).json({ error: 'Not authenticated' });
  try {
    const payload = jwt.verify(token, JWT_SECRET);
    req.user = payload;
    next();
  } catch (e) {
    return res.status(401).json({ error: 'Invalid token' });
  }
}

/* ---------- API ---------- */

// signup
app.post('/api/signup', async (req, res) => {
  const { email, username, password } = req.body;
  if (!email || !password || !username) return res.status(400).json({ error: 'Missing fields' });

  const id = uuidv4();
  const password_hash = await bcrypt.hash(password, 10);

  db.run('INSERT INTO users (id,email,username,password_hash,balance) VALUES (?,?,?,?,?)',
    [id, email.toLowerCase(), username, password_hash, 0],
    function (err) {
      if (err) {
        return res.status(400).json({ error: 'User exists or invalid' });
      }
      const token = jwt.sign({ id, email, username }, JWT_SECRET, { expiresIn: '7d' });
      res.cookie('token', token, { httpOnly: true });
      return res.json({ ok: true });
    });
});

// login
app.post('/api/login', (req, res) => {
  const { credential, password } = req.body; // credential can be email or username
  if (!credential || !password) return res.status(400).json({ error: 'Missing' });

  db.get('SELECT * FROM users WHERE email = ? OR username = ?', [credential.toLowerCase(), credential], async (err, user) => {
    if (err || !user) return res.status(400).json({ error: 'Invalid credentials' });
    const match = await bcrypt.compare(password, user.password_hash);
    if (!match) return res.status(400).json({ error: 'Invalid credentials' });

    // If user has 2FA enabled, indicate that client should verify TOTP
    if (user.twofa_enabled) {
      // Set a temporary session token to allow 2FA verification (short-lived)
      const tmp = jwt.sign({ id: user.id, twofa: true }, JWT_SECRET, { expiresIn: '5m' });
      return res.json({ require2fa: true, tmpToken: tmp });
    }

    const token = jwt.sign({ id: user.id, email: user.email, username: user.username }, JWT_SECRET, { expiresIn: '7d' });
    res.cookie('token', token, { httpOnly: true });
    return res.json({ ok: true });
  });
});

// Verify 2FA (on login)
app.post('/api/verify-2fa', (req, res) => {
  const { tmpToken, code } = req.body;
  if (!tmpToken || !code) return res.status(400).json({ error: 'Missing' });
  try {
    const payload = jwt.verify(tmpToken, JWT_SECRET);
    if (!payload.twofa) return res.status(400).json({ error: 'Invalid temp token' });

    db.get('SELECT * FROM users WHERE id = ?', [payload.id], (err, user) => {
      if (err || !user) return res.status(400).json({ error: 'User not found' });
      const verified = speakeasy.totp.verify({ secret: user.twofa_secret, encoding: 'base32', token: code, window: 1 });
      if (!verified) return res.status(400).json({ error: 'Invalid 2FA code' });

      const token = jwt.sign({ id: user.id, email: user.email, username: user.username }, JWT_SECRET, { expiresIn: '7d' });
      res.cookie('token', token, { httpOnly: true });
      return res.json({ ok: true });
    });
  } catch (e) {
    return res.status(400).json({ error: 'Invalid or expired token' });
  }
});

// Get current user / profile
app.get('/api/me', authMiddleware, (req, res) => {
  db.get('SELECT id,email,username,balance,twofa_enabled FROM users WHERE id = ?', [req.user.id], (err, user) => {
    if (err || !user) return res.status(400).json({ error: 'User not found' });
    res.json({ user });
  });
});

// Generate 2FA secret (for setup)
app.post('/api/2fa/setup', authMiddleware, (req, res) => {
  const secret = speakeasy.generateSecret({ length: 20 });
  qrcode.toDataURL(secret.otpauth_url, (err, data_url) => {
    if (err) return res.status(500).json({ error: 'QR error' });
    // temporarily return secret to client (client will call confirm to enable)
    res.json({ secret: secret.base32, qr: data_url });
  });
});

// Confirm enabling 2FA
app.post('/api/2fa/confirm', authMiddleware, (req, res) => {
  const { secret, token } = req.body;
  if (!secret || !token) return res.status(400).json({ error: 'Missing' });
  const ok = speakeasy.totp.verify({ secret, encoding: 'base32', token, window: 1 });
  if (!ok) return res.status(400).json({ error: 'Invalid code' });

  db.run('UPDATE users SET twofa_secret = ?, twofa_enabled = 1 WHERE id = ?', [secret, req.user.id], function (err) {
    if (err) return res.status(500).json({ error: 'DB error' });
    res.json({ ok: true });
  });
});

// Add funds (dummy method)
app.post('/api/add-funds', authMiddleware, (req, res) => {
  const { amount } = req.body;
  const amt = parseFloat(amount);
  if (isNaN(amt) || amt <= 0) return res.status(400).json({ error: 'Invalid amount' });

  db.run('UPDATE users SET balance = balance + ? WHERE id = ?', [amt, req.user.id], function (err) {
    if (err) return res.status(500).json({ error: 'DB error' });
    const txid = uuidv4();
    const now = new Date().toISOString();
    db.run('INSERT INTO transactions (id,from_user_id,to_user_id,amount,memo,created_at) VALUES (?,?,?,?,?,?)',
      [txid, null, req.user.id, amt, 'Add funds (dummy)', now]);
    // send email
    db.get('SELECT email FROM users WHERE id = ?', [req.user.id], (e, u) => {
      if (!e && u) {
        transporter.sendMail({
          from: process.env.SMTP_USER,
          to: u.email,
          subject: `Wallet funded: ${amt}`,
          text: `Your wallet was funded with ${amt}.\nTransaction ID: ${txid}`
        }).catch(()=>{});
      }
    });
    res.json({ ok: true, txid });
  });
});

// Transfer money
app.post('/api/transfer', authMiddleware, (req, res) => {
  const { to, amount, memo } = req.body; // 'to' is email or username
  const amt = parseFloat(amount);
  if (!to || isNaN(amt) || amt <= 0) return res.status(400).json({ error: 'Invalid' });

  db.get('SELECT * FROM users WHERE email = ? OR username = ?', [to.toLowerCase(), to], (err, target) => {
    if (err || !target) return res.status(400).json({ error: 'Recipient not found' });
    if (target.id === req.user.id) return res.status(400).json({ error: 'Cannot send to self' });

    db.get('SELECT balance FROM users WHERE id = ?', [req.user.id], (err2, row) => {
      if (err2 || !row) return res.status(400).json({ error: 'Sender not found' });
      if (row.balance < amt) return res.status(400).json({ error: 'Insufficient balance' });

      const txid = uuidv4();
      const now = new Date().toISOString();
      db.serialize(() => {
        db.run('UPDATE users SET balance = balance - ? WHERE id = ?', [amt, req.user.id]);
        db.run('UPDATE users SET balance = balance + ? WHERE id = ?', [amt, target.id]);
        db.run('INSERT INTO transactions (id,from_user_id,to_user_id,amount,memo,created_at) VALUES (?,?,?,?,?,?)',
          [txid, req.user.id, target.id, amt, memo || '', now]);
      });

      // send email notifications
      db.get('SELECT email FROM users WHERE id = ?', [req.user.id], (e1, s) => {
        db.get('SELECT email FROM users WHERE id = ?', [target.id], (e2, t) => {
          if (s && s.email) {
            transporter.sendMail({
              from: process.env.SMTP_USER,
              to: s.email,
              subject: `You sent ${amt}`,
              text: `You sent ${amt} to ${target.username || target.email}. TX: ${txid}`
            }).catch(()=>{});
          }
          if (t && t.email) {
            transporter.sendMail({
              from: process.env.SMTP_USER,
              to: t.email,
              subject: `You received ${amt}`,
              text: `You received ${amt} from ${req.user.username || req.user.email}. TX: ${txid}`
            }).catch(()=>{});
          }
        });
      });

      res.json({ ok: true, txid });
    });
  });
});

// Get transactions for logged-in user
app.get('/api/transactions', authMiddleware, (req, res) => {
  db.all('SELECT * FROM transactions WHERE from_user_id = ? OR to_user_id = ? ORDER BY created_at DESC LIMIT 200', [req.user.id, req.user.id], (err, rows) => {
    if (err) return res.status(500).json({ error: 'DB' });
    res.json({ transactions: rows });
  });
});

// logout
app.post('/api/logout', (req, res) => {
  res.clearCookie('token');
  res.json({ ok: true });
});

// password reset request
app.post('/api/reset-request', (req, res) => {
  const { email } = req.body;
  if (!email) return res.status(400).json({ error: 'Missing' });
  const token = uuidv4();
  db.run('UPDATE users SET reset_token = ? WHERE email = ?', [token, email.toLowerCase()], function (err) {
    if (err) return res.status(400).json({ error: 'Email not found' });
    const link = `${APP_BASE_URL}/reset_password.html?token=${token}`;
    transporter.sendMail({
      from: process.env.SMTP_USER,
      to: email,
      subject: 'Password reset',
      text: `Reset your password: ${link}`
    }).catch(()=>{});
    res.json({ ok: true });
  });
});

// perform password reset
app.post('/api/reset-password', async (req, res) => {
  const { token, newPassword } = req.body;
  if (!token || !newPassword) return res.status(400).json({ error: 'Missing' });
  const hash = await bcrypt.hash(newPassword, 10);
  db.run('UPDATE users SET password_hash = ?, reset_token = NULL WHERE reset_token = ?', [hash, token], function (err) {
    if (err) return res.status(400).json({ error: 'Token invalid' });
    res.json({ ok: true });
  });
});

app.listen(3000, () => {
  console.log('Server running on http://localhost:3000');
});
