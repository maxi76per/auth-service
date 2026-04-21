const express = require('express');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const rateLimit = require('express-rate-limit');
const cookieParser = require('cookie-parser');
const path = require('path');
const crypto = require('crypto');

const app = express();
const PORT = 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'super_secret_key_for_jwt_auth_123';

// Middleware
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser());
app.use(express.static(path.join(__dirname, 'public')));

// In-memory Database
const users = []; // { id, username, passwordHash, role, lastLogin, activeSessionId, resetToken }
let currentId = 1;

// --- Security Mechanisms ---

// Rate Limiting for Login (3 attempts per minute)
const loginLimiter = rateLimit({
    windowMs: 60 * 1000, // 1 minute
    max: 3, // 3 attempts
    message: { error: 'Слишком много попыток входа. Пожалуйста, подождите 1 минуту.' },
    standardHeaders: true,
    legacyHeaders: false,
});

// HTML Escaping to prevent XSS
const escapeHTML = (str) => {
    return str.replace(/[&<>'"]/g, 
        tag => ({
            '&': '&amp;',
            '<': '&lt;',
            '>': '&gt;',
            "'": '&#39;',
            '"': '&quot;'
        }[tag] || tag)
    );
};

// Middleware: Authenticate User via JWT in HTTP-Only Cookie
const authenticate = (req, res, next) => {
    const token = req.cookies.token;
    if (!token) {
        return res.status(401).json({ error: 'Необходима авторизация' });
    }

    try {
        const decoded = jwt.verify(token, JWT_SECRET);
        
        // Find user
        const user = users.find(u => u.id === decoded.userId);
        if (!user) {
            return res.status(401).json({ error: 'Пользователь не найден' });
        }

        // Check for parallel sessions (Compare sessionId)
        if (user.activeSessionId !== decoded.sessionId) {
            return res.status(401).json({ error: 'Сессия недействительна (возможно, выполнен вход с другого устройства)' });
        }

        // Token Auto-refresh (if less than 5 mins remaining)
        const currentTimestamp = Math.floor(Date.now() / 1000);
        if (decoded.exp - currentTimestamp < 300) {
            const newToken = jwt.sign(
                { userId: user.id, role: user.role, sessionId: user.activeSessionId },
                JWT_SECRET,
                { expiresIn: '15m' }
            );
            res.cookie('token', newToken, { httpOnly: true, secure: false, maxAge: 15 * 60 * 1000 });
        }

        req.user = user;
        next();
    } catch (err) {
        return res.status(401).json({ error: 'Неверный или просроченный токен' });
    }
};

// Middleware: Require Admin Role
const requireAdmin = (req, res, next) => {
    if (req.user.role !== 'admin') {
        console.log(`[ACCESS DENIED] Попытка доступа к админ-панели пользователем: ${req.user.username}`);
        return res.status(403).json({ error: 'Доступ запрещен. Требуются права администратора.' });
    }
    next();
};

// --- API Routes ---

// 1. Register
app.post('/api/register', async (req, res) => {
    const { username, password, role } = req.body;
    
    if (!username || !password) {
        return res.status(400).json({ error: 'Имя пользователя и пароль обязательны' });
    }

    // Check if user exists
    if (users.find(u => u.username === username)) {
        return res.status(400).json({ error: 'Пользователь уже существует' });
    }

    // Hash password with salt (bcrypt handles salt generation automatically)
    const saltRounds = 10;
    const passwordHash = await bcrypt.hash(password, saltRounds);

    const newUser = {
        id: currentId++,
        username: escapeHTML(username),
        passwordHash: passwordHash,
        role: role && ['user', 'moderator', 'admin'].includes(role) ? role : 'user',
        lastLogin: null,
        activeSessionId: null,
        resetToken: null
    };

    users.push(newUser);
    console.log(`[REGISTER] Новый пользователь: ${newUser.username} (Роль: ${newUser.role})`);
    res.status(201).json({ message: 'Регистрация успешна' });
});

// 2. Login
app.post('/api/login', loginLimiter, async (req, res) => {
    const { username, password } = req.body;
    
    console.log(`[LOGIN ATTEMPT] Пользователь: ${username}`);

    const user = users.find(u => u.username === username);
    if (!user) {
        console.log(`[LOGIN FAILED] Пользователь не найден: ${username}`);
        return res.status(401).json({ error: 'Неверное имя пользователя или пароль' });
    }

    const isMatch = await bcrypt.compare(password, user.passwordHash);
    if (!isMatch) {
        console.log(`[LOGIN FAILED] Неверный пароль: ${username}`);
        return res.status(401).json({ error: 'Неверное имя пользователя или пароль' });
    }

    // Success login
    user.lastLogin = new Date();
    
    // Generate new Session ID (Prevents parallel sessions)
    const sessionId = crypto.randomBytes(16).toString('hex');
    user.activeSessionId = sessionId;

    console.log(`[LOGIN SUCCESS] Пользователь: ${username}`);

    // Generate JWT (15 mins)
    const token = jwt.sign(
        { userId: user.id, role: user.role, sessionId: sessionId },
        JWT_SECRET,
        { expiresIn: '15m' }
    );

    // Send HTTP-Only Cookie
    res.cookie('token', token, {
        httpOnly: true,
        secure: false, // true in production with HTTPS
        maxAge: 15 * 60 * 1000 // 15 mins
    });

    res.json({ message: 'Вход выполнен успешно', role: user.role });
});

// 3. Logout
app.post('/api/logout', (req, res) => {
    res.clearCookie('token');
    res.json({ message: 'Вы вышли из системы' });
});

// 4. Get Current User Data
app.get('/api/me', authenticate, (req, res) => {
    res.json({
        id: req.user.id,
        username: req.user.username,
        role: req.user.role,
        lastLogin: req.user.lastLogin
    });
});

// 5. Admin Data (Protected Route)
app.get('/api/admin-data', authenticate, requireAdmin, (req, res) => {
    const safeUsers = users.map(u => ({
        id: u.id,
        username: u.username,
        role: u.role,
        lastLogin: u.lastLogin
    }));
    res.json({ message: 'Добро пожаловать в секретную панель администратора', users: safeUsers });
});

// --- Password Recovery (Extra Task) ---

// Request Reset
app.post('/api/recover', (req, res) => {
    const { username } = req.body;
    const user = users.find(u => u.username === username);
    
    if (!user) {
        // Return success anyway to prevent username enumeration
        return res.json({ message: 'Если пользователь существует, токен сброса был сгенерирован.' });
    }

    // Generate one-time reset token
    const resetToken = crypto.randomBytes(32).toString('hex');
    user.resetToken = resetToken;
    
    console.log(`[PASSWORD RECOVER] Токен для ${username}: ${resetToken}`);
    
    // In a real app, send an email. For this lab, return it in response (or console).
    res.json({ message: 'Токен сброса сгенерирован. В реальном приложении он был бы отправлен на почту.', token: resetToken });
});

// Apply Reset
app.post('/api/reset', async (req, res) => {
    const { username, token, newPassword } = req.body;
    const user = users.find(u => u.username === username);

    if (!user || user.resetToken !== token) {
        return res.status(400).json({ error: 'Неверный пользователь или токен сброса' });
    }

    // Update password
    const passwordHash = await bcrypt.hash(newPassword, 10);
    user.passwordHash = passwordHash;
    user.resetToken = null; // Invalidate token
    
    // Invalidate existing sessions
    user.activeSessionId = null;

    console.log(`[PASSWORD RESET SUCCESS] Пользователь: ${username}`);
    res.json({ message: 'Пароль успешно изменен. Пожалуйста, войдите с новым паролем.' });
});


// Start Server
app.listen(PORT, () => {
    console.log(`Сервер микросервиса аутентификации запущен на http://localhost:${PORT}`);
    console.log(`Для проверки откройте http://localhost:${PORT} в браузере.`);
});
