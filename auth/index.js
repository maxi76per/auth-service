const express = require('express');
const bcrypt = require('bcryptjs');
const crypto = require('crypto');
const jwt = require('jsonwebtoken');

const app = express();
app.use(express.json());

const PORT = Number(process.env.PORT) || 3000;
const JWT_SECRET = 'secret_key';
const MAX_LOGIN_ATTEMPTS = 3;
const LOCK_TIME_MS = 60 * 1000;

// In-memory user store for the assignment demo.
let users = [
  createUser(1, 'admin', 'admin123', 'admin'),
  createUser(2, 'moderator', 'moderator123', 'moderator')
];

app.post('/register', async (req, res) => {
  const { username, password, role = 'user' } = req.body;

  if (!username || !password) {
    return res.status(400).json({ error: 'Username and password are required' });
  }

  if (!['user', 'moderator', 'admin'].includes(role)) {
    return res.status(400).json({ error: 'Invalid role' });
  }

  const existingUser = users.find((u) => u.username === username);
  if (existingUser) {
    return res.status(400).json({ error: 'User already exists' });
  }

  const passwordHash = await bcrypt.hash(password, 10);

  const newUser = {
    id: users.length + 1,
    username,
    passwordHash,
    role,
    lastLogin: null,
    activeToken: null,
    failedLoginAttempts: 0,
    lockUntil: null
  };

  users.push(newUser);

  res.json({
    message: 'User registered',
    user: { id: newUser.id, username: newUser.username, role: newUser.role }
  });
});

app.post('/login', async (req, res) => {
  const { username, password } = req.body;

  if (!username || !password) {
    return res.status(400).json({ error: 'Username and password are required' });
  }

  const user = users.find((u) => u.username === username);
  if (!user) {
    logAttempt(username, false);
    return res.status(401).json({ error: 'Invalid credentials' });
  }

  if (user.lockUntil && user.lockUntil > Date.now()) {
    return res.status(423).json({ error: 'Account locked. Try again in 1 minute.' });
  }

  const isValid = await bcrypt.compare(password, user.passwordHash);
  if (!isValid) {
    user.failedLoginAttempts += 1;

    if (user.failedLoginAttempts >= MAX_LOGIN_ATTEMPTS) {
      user.lockUntil = Date.now() + LOCK_TIME_MS;
      user.failedLoginAttempts = 0;
    }

    logAttempt(username, false);
    return res.status(401).json({ error: 'Invalid credentials' });
  }

  user.failedLoginAttempts = 0;
  user.lockUntil = null;

  const token = jwt.sign(
    { userId: user.id, role: user.role, sessionId: crypto.randomUUID() },
    JWT_SECRET,
    { expiresIn: '15m' }
  );

  user.lastLogin = new Date();
  user.activeToken = token;

  logAttempt(username, true);

  res.json({ token });
});

function authenticate(req, res, next) {
  const header = req.headers.authorization;

  if (!header) {
    return res.status(401).json({ error: 'No token' });
  }

  const token = header.split(' ')[1];

  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    const user = users.find((u) => u.id === decoded.userId);

    if (!user || user.activeToken !== token) {
      return res.status(401).json({ error: 'Session invalid' });
    }

    req.user = decoded;
    next();
  } catch {
    return res.status(401).json({ error: 'Invalid token' });
  }
}

app.get('/admin', authenticate, (req, res) => {
  if (req.user.role !== 'admin') {
    return res.status(403).json({ error: 'Forbidden' });
  }

  res.json({ message: 'Admin panel' });
});

function logAttempt(username, success) {
  console.log({
    username,
    success,
    time: new Date()
  });
}

function createUser(id, username, password, role) {
  return {
    id,
    username,
    passwordHash: bcrypt.hashSync(password, 10),
    role,
    lastLogin: null,
    activeToken: null,
    failedLoginAttempts: 0,
    lockUntil: null
  };
}

app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});

