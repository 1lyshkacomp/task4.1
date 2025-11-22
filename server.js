require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const helmet = require('helmet');
const cors = require('cors');
const rateLimit = require('express-rate-limit');
const { body, validationResult } = require('express-validator');
const User = require('./models/User.js');

const app = express();
const PORT = process.env.PORT || 3000;

// --- Middleware ---
app.use(helmet());
app.use(cors()); // при необходимости можно ограничить origin
app.use(express.json());
app.use(express.static('public'));

// Ограничитель запросов — базовый
const apiLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 минут
  max: 100, // максимум 100 запросов с IP за 15 минут
  standardHeaders: true,
  legacyHeaders: false
});
app.use('/api/', apiLimiter);

// --- MongoDB connection ---
const MONGO_URI = process.env.MONGO_URI || 'mongodb://127.0.0.1:27017/userDB';
mongoose.connect(MONGO_URI)
  .then(() => console.log('MongoDB connected'))
  .catch(err => {
    console.error('MongoDB connection error:', err.message);
    process.exit(1);
  });

// --- Basic Auth middleware ---
const basicAuth = async (req, res, next) => {
  try {
    const header = req.headers.authorization || '';
    if (!header.startsWith('Basic ')) {
      return res.status(401).json({ error: 'Требуется авторизация (Basic)' });
    }
    const b64 = header.split(' ')[1] || '';
    const decoded = Buffer.from(b64, 'base64').toString('utf8');
    const sepIndex = decoded.indexOf(':');
    if (sepIndex === -1) {
      return res.status(401).json({ error: 'Неверный формат авторизации' });
    }
    const nickname = decoded.slice(0, sepIndex);
    const password = decoded.slice(sepIndex + 1);

    if (!nickname || !password) return res.status(401).json({ error: 'Пустые креденшелы' });

    const user = await User.findOne({ nickname }).exec();
    if (!user || !user.checkPassword(password)) {
      return res.status(401).json({ error: 'Неверный логин или пароль' });
    }

    req.user = user;
    next();
  } catch (err) {
    console.error('Auth error:', err);
    res.status(500).json({ error: 'Ошибка авторизации' });
  }
};

// --- Routes ---

// 1) Регистрация
app.post('/api/register',
  // Валидация
  [
    body('nickname').isAlphanumeric().isLength({ min: 3, max: 30 }).withMessage('Ник должен быть 3-30 символов, буквы/цифры'),
    body('firstName').isLength({ min: 1, max: 50 }).withMessage('Имя обязательное'),
    body('lastName').isLength({ min: 1, max: 50 }).withMessage('Фамилия обязательная'),
    body('password').isLength({ min: 8 }).withMessage('Пароль минимум 8 символов')
  ],
  async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) return res.status(400).json({ errors: errors.array() });

    const { nickname, firstName, lastName, password } = req.body;
    try {
      const user = new User({ nickname, firstName, lastName });
      user.setPassword(password);
      await user.save();
      res.status(201).json({ message: 'Пользователь создан' });
    } catch (err) {
      if (err.code === 11000) { // duplicate key
        return res.status(409).json({ error: 'Никнейм уже занят' });
      }
      console.error('Registration error:', err);
      res.status(500).json({ error: 'Ошибка сервера при регистрации' });
    }
  }
);

// 2) Публичный список пользователей (с пагинацией)
app.get('/api/users', async (req, res) => {
  try {
    const page = Math.max(1, parseInt(req.query.page) || 1);
    const limit = Math.min(100, parseInt(req.query.limit) || 10);
    const skip = (page - 1) * limit;

    const [users, total] = await Promise.all([
      User.find({}, 'nickname firstName lastName').skip(skip).limit(limit).lean(),
      User.countDocuments()
    ]);

    res.json({
      page,
      limit,
      total,
      pages: Math.ceil(total / limit),
      users
    });
  } catch (err) {
    console.error('Users list error:', err);
    res.status(500).json({ error: 'Ошибка сервера' });
  }
});

// 3) Получить профиль (защищено Basic Auth)
app.get('/api/me', basicAuth, (req, res) => {
  const u = req.user;
  res.json({
    message: 'Авторизация успешна',
    user: { nickname: u.nickname, firstName: u.firstName, lastName: u.lastName }
  });
});

// 4) Обновление профиля (firstName/lastName)
app.put('/api/update', basicAuth, [
  body('firstName').optional().isLength({ min: 1, max: 50 }),
  body('lastName').optional().isLength({ min: 1, max: 50 })
], async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) return res.status(400).json({ errors: errors.array() });

  try {
    const { firstName, lastName } = req.body;
    if (firstName) req.user.firstName = firstName;
    if (lastName) req.user.lastName = lastName;
    await req.user.save();
    res.json({ message: 'Профиль обновлён' });
  } catch (err) {
    console.error('Update error:', err);
    res.status(500).json({ error: 'Ошибка сервера при обновлении' });
  }
});

// 5) Смена пароля (требует старый пароль)
app.put('/api/change-password', basicAuth, [
  body('oldPassword').isLength({ min: 1 }),
  body('newPassword').isLength({ min: 8 }).withMessage('Новый пароль минимум 8 символов')
], async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) return res.status(400).json({ errors: errors.array() });

  try {
    const { oldPassword, newPassword } = req.body;
    if (!req.user.checkPassword(oldPassword)) {
      return res.status(401).json({ error: 'Старый пароль неверен' });
    }
    req.user.setPassword(newPassword);
    await req.user.save();
    res.json({ message: 'Пароль успешно изменён' });
  } catch (err) {
    console.error('Change password error:', err);
    res.status(500).json({ error: 'Ошибка сервера при смене пароля' });
  }
});

// Fallback
app.use((req, res) => {
  res.status(404).json({ error: 'Маршрут не найден' });
});

// Start
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});
