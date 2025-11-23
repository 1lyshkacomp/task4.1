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
app.use(cors());
app.use(express.json());
app.use(express.static('public')); // Раздает frontend

// Ограничитель запросов (Лимит увеличен для тестов в CodeSandbox)
const apiLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 минут
  max: 300, // Увеличил до 300, чтобы ты случайно не заблокировал себя при тестах
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: "Слишком много запросов, подождите немного." }
});
app.use('/api/', apiLimiter);

// --- MongoDB connection ---
// Если переменной нет, приложение упадет с понятной ошибкой, а не зависнет
if (!process.env.MONGO_URI) {
    console.error("ОШИБКА: Не задан MONGO_URI в переменных окружения!");
}

mongoose.connect(process.env.MONGO_URI)
  .then(() => console.log('✅ MongoDB connected successfully'))
  .catch(err => console.error('❌ MongoDB connection error:', err.message));

// --- Basic Auth middleware ---
const basicAuth = async (req, res, next) => {
  try {
    const header = req.headers.authorization || '';
    if (!header.startsWith('Basic ')) {
      return res.status(401).json({ error: 'Требуется авторизация (Basic)' });
    }
    
    // Декодируем base64
    const b64 = header.split(' ')[1];
    const decoded = Buffer.from(b64, 'base64').toString('utf8');
    const sepIndex = decoded.indexOf(':');
    
    if (sepIndex === -1) {
      return res.status(401).json({ error: 'Неверный формат авторизации' });
    }
    
    const nickname = decoded.slice(0, sepIndex);
    const password = decoded.slice(sepIndex + 1);

    if (!nickname || !password) return res.status(401).json({ error: 'Пустые данные входа' });

    const user = await User.findOne({ nickname });
    
    // Проверяем пароль
    if (!user || !user.checkPassword(password)) {
      // Имитируем задержку для безопасности (защита от перебора)
      await new Promise(resolve => setTimeout(resolve, 100)); 
      return res.status(401).json({ error: 'Неверный логин или пароль' });
    }

    req.user = user;
    next();
  } catch (err) {
    console.error('Auth error:', err);
    res.status(500).json({ error: 'Внутренняя ошибка авторизации' });
  }
};

// --- Routes ---

// 1. Регистрация
app.post('/api/register',
  [
    body('nickname').trim().isLength({ min: 3, max: 30 }).withMessage('Ник: 3-30 символов'),
    body('firstName').trim().notEmpty().withMessage('Имя обязательно'),
    body('lastName').trim().notEmpty().withMessage('Фамилия обязательна'),
    body('password').isLength({ min: 6 }).withMessage('Пароль минимум 6 символов')
  ],
  async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) return res.status(400).json({ errors: errors.array() });

    try {
      const { nickname, firstName, lastName, password } = req.body;
      const user = new User({ nickname, firstName, lastName });
      user.setPassword(password);
      await user.save();
      res.status(201).json({ message: 'Пользователь успешно создан!' });
    } catch (err) {
      if (err.code === 11000) {
        return res.status(409).json({ error: 'Такой никнейм уже занят' });
      }
      res.status(500).json({ error: 'Ошибка сервера при регистрации' });
    }
  }
);

// 2. Список пользователей (Пагинация)
app.get('/api/users', async (req, res) => {
  try {
    const page = Math.max(1, parseInt(req.query.page) || 1);
    const limit = Math.min(50, parseInt(req.query.limit) || 10);
    const skip = (page - 1) * limit;

    const [users, total] = await Promise.all([
      User.find({}, 'nickname firstName lastName createdAt').skip(skip).limit(limit).lean(),
      User.countDocuments()
    ]);

    res.json({
      page,
      limit,
      total,
      totalPages: Math.ceil(total / limit),
      data: users
    });
  } catch (err) {
    res.status(500).json({ error: 'Ошибка получения списка' });
  }
});

// 3. Получить свой профиль (Защищено)
app.get('/api/me', basicAuth, (req, res) => {
  res.json({
    message: 'Успешный вход',
    user: { 
        nickname: req.user.nickname, 
        firstName: req.user.firstName, 
        lastName: req.user.lastName 
    }
  });
});

// 4. Обновить профиль (Защищено)
app.put('/api/update', basicAuth, async (req, res) => {
    try {
        const { firstName, lastName } = req.body;
        if (firstName) req.user.firstName = firstName;
        if (lastName) req.user.lastName = lastName;
        await req.user.save();
        res.json({ message: 'Профиль обновлен' });
    } catch (err) {
        res.status(500).json({ error: 'Ошибка обновления' });
    }
});

// 5. Сменить пароль (Защищено)
app.put('/api/change-password', basicAuth, [
    body('newPassword').isLength({ min: 6 }).withMessage('Новый пароль слишком короткий')
], async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) return res.status(400).json({ errors: errors.array() });

    try {
        const { oldPassword, newPassword } = req.body;
        // Проверяем старый пароль еще раз для надежности
        if (!req.user.checkPassword(oldPassword)) {
            return res.status(401).json({ error: 'Старый пароль неверен' });
        }
        
        req.user.setPassword(newPassword);
        await req.user.save();
        res.json({ message: 'Пароль успешно изменен' });
    } catch (err) {
        res.status(500).json({ error: 'Ошибка смены пароля' });
    }
});

// Запуск
app.listen(PORT, () => {
  console.log(`🚀 Server running on port ${PORT}`);
});