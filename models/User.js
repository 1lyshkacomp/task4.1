const mongoose = require('mongoose');
const crypto = require('crypto');

const userSchema = new mongoose.Schema(
  {
    nickname: { type: String, required: true, unique: true, index: true },
    firstName: { type: String, required: true },
    lastName: { type: String, required: true },

    passwordHash: { type: String, select: false },
    salt: { type: String, select: false },

    pbkdf2Iterations: { type: Number, default: 100000, select: false },
    pbkdf2Keylen: { type: Number, default: 64, select: false },
    pbkdf2Digest: { type: String, default: 'sha512', select: false },

    // NEW — технические поля
    created_at: { type: Date, default: Date.now, select: false },
    updated_at: { type: Date, default: Date.now, select: false },
    deleted_at: { type: Date, default: null, select: false }
  }
);

// Хеширование пароля
userSchema.methods.setPassword = function (password) {
  this.salt = crypto.randomBytes(16).toString('hex');

  const iterations = this.pbkdf2Iterations;
  const keylen = this.pbkdf2Keylen;
  const digest = this.pbkdf2Digest;

  const hashBuffer = crypto.pbkdf2Sync(password, this.salt, iterations, keylen, digest);
  this.passwordHash = hashBuffer.toString('hex');
};

// Проверка пароля
userSchema.methods.checkPassword = function (password) {
  if (!this.passwordHash || !this.salt) return false;

  const iterations = this.pbkdf2Iterations;
  const keylen = this.pbkdf2Keylen;
  const digest = this.pbkdf2Digest;

  const hashBuffer = crypto.pbkdf2Sync(password, this.salt, iterations, keylen, digest);
  const storedBuffer = Buffer.from(this.passwordHash, 'hex');

  if (storedBuffer.length !== hashBuffer.length) return false;
  return crypto.timingSafeEqual(storedBuffer, hashBuffer);
};

// Перед сохранением обновляем updated_at
userSchema.pre('save', function (next) {
  this.updated_at = new Date();
  next();
});

module.exports = mongoose.model('User', userSchema);
