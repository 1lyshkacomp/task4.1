require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const helmet = require('helmet');
const cors = require('cors');
const rateLimit = require('express-rate-limit');
const { body, validationResult } = require('express-validator');
const User = require('./models/User');

const app = express();
const PORT = process.env.PORT || 3000;

// --- Middleware ---
app.use(helmet());
app.use(cors());
app.use(express.json());
app.use(express.static('public'));

const apiLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 300,
  standardHeaders: true,
  legacyHeaders: false,
});
app.use('/api/', apiLimiter);

// --- MongoDB ---
if (!process.env.MONGO_URI) console.error("ОШИБКА: Не задан MONGO_URI!");
mongoose.connect(process.env.MONGO_URI)
  .then(() => console.log('✅ MongoDB connected'))
  .catch(err => console.error('❌ MongoDB error:', err.message));

// --- Basic Auth ---
const basicAuth = async (req, res, next) => {
  try {
    const header = req.headers.authorization || '';
    if (!header.startsWith('Basic ')) return res.status(401).json({ error: 'Auth required' });
    
    const b64 = header.split(' ')[1];
    const [nickname, password] = Buffer.from(b64, 'base64').toString('utf8').split(':');

    if (!nickname || !password) return res.status(401).json({ error: 'No credentials' });

    // Ищем только НЕ УДАЛЕННЫХ пользователей
    const user = await User.findOne({ nickname, deleted_at: null }).select('+passwordHash +salt +updated_at');
    
    if (!user || !user.checkPassword(password)) {
      await new Promise(r => setTimeout(r, 100)); 
      return res.status(401).json({ error: 'Wrong credentials' });
    }

    req.user = user;
    next();
  } catch (err) {
    res.status(500).json({ error: 'Auth error' });
  }
};

// --- ROUTES ---

// 1. Регистрация (Без изменений)
app.post('/api/register',
  [
    body('nickname').trim().isLength({ min: 3, max: 30 }),
    body('firstName').trim().notEmpty(),
    body('lastName').trim().notEmpty(),
    body('password').isLength({ min: 6 })
  ],
  async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) return res.status(400).json({ errors: errors.array() });

    try {
      const { nickname, firstName, lastName, password } = req.body;
      const user = new User({ nickname, firstName, lastName });
      user.setPassword(password);
      await user.save();
      res.status(201).json({ message: 'Created' });
    } catch (err) {
      if (err.code === 11000) return res.status(409).json({ error: 'Nickname taken' });
      res.status(500).json({ error: 'Server error' });
    }
  }
);

// 2. GET /api/me (С Last-Modified)
app.get('/api/me', basicAuth, (req, res) => {
  // Устанавливаем заголовок
  if (req.user.updated_at) {
    res.setHeader('Last-Modified', new Date(req.user.updated_at).toUTCString());
  }

  res.json({
    nickname: req.user.nickname,
    firstName: req.user.firstName,
    lastName: req.user.lastName
  });
});

// 3. PUT /api/update (С проверкой If-Unmodified-Since)
app.put('/api/update', basicAuth, async (req, res) => {
  try {
    const user = req.user;
    const clientHeader = req.headers['if-unmodified-since'];

    // Если клиент прислал заголовок - проверяем
    if (clientHeader) {
        const clientTime = new Date(clientHeader).getTime();
        const serverTime = new Date(user.updated_at).getTime();

        // ⚠️ ИСПРАВЛЕНИЕ: Даем фору в 1 секунду (1000мс) на разницу форматов
        if (serverTime > clientTime + 1000) {
            return res.status(412).json({ 
                error: 'Precondition Failed: Данные устарели. Обновите страницу.' 
            });
        }
    } else {
        // Опционально: можно требовать заголовок всегда (428 Precondition Required)
        // Но для простоты тестов пока оставим так
    }

    const { firstName, lastName } = req.body;
    if (firstName) user.firstName = firstName;
    if (lastName) user.lastName = lastName;
    
    // Mongoose обновит updated_at автоматически (см. pre save в модели)
    await user.save();
    
    // Возвращаем новую дату
    res.setHeader('Last-Modified', new Date(user.updated_at).toUTCString());
    res.json({ message: 'Updated' });
  } catch (err) {
    res.status(500).json({ error: 'Update error' });
  }
});

// 4. DELETE /api/delete (Soft Delete)
app.delete('/api/delete', basicAuth, async (req, res) => {
  try {
    const user = req.user;
    user.deleted_at = new Date(); // Ставим метку удаления
    await user.save();
    res.json({ message: 'Account soft-deleted' });
  } catch (err) {
    res.status(500).json({ error: 'Delete error' });
  }
});

// 5. GET /api/users (Скрываем удаленных)
app.get('/api/users', async (req, res) => {
  try {
    const page = Math.max(1, parseInt(req.query.page) || 1);
    const limit = Math.min(50, parseInt(req.query.limit) || 10);
    const skip = (page - 1) * limit;

    const query = { deleted_at: null }; // Только живые

    const [users, total] = await Promise.all([
      User.find(query, 'nickname firstName lastName').skip(skip).limit(limit).lean(),
      User.countDocuments(query)
    ]);

    res.json({
      page, limit, total,
      data: users
    });
  } catch (err) {
    res.status(500).json({ error: 'List error' });
  }
});

app.listen(PORT, () => console.log(`🚀 Server on ${PORT}`));