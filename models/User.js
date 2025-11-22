const mongoose = require('mongoose');
const crypto = require('crypto');

const userSchema = new mongoose.Schema({
  nickname: { type: String, required: true, unique: true, index: true },
  firstName: { type: String, required: true },
  lastName: { type: String, required: true },
  passwordHash: { type: String },
  salt: { type: String },
  pbkdf2Iterations: { type: Number, default: 120000 }, // сохраняем текущие параметры
  pbkdf2Keylen: { type: Number, default: 64 },
  pbkdf2Digest: { type: String, default: 'sha512' }
}, { timestamps: true });

userSchema.methods.setPassword = function(password) {
  const iterations = this.pbkdf2Iterations || 120000;
  const keylen = this.pbkdf2Keylen || 64;
  const digest = this.pbkdf2Digest || 'sha512';
  this.salt = crypto.randomBytes(16).toString('hex');
  const hashBuffer = crypto.pbkdf2Sync(password, this.salt, iterations, keylen, digest);
  this.passwordHash = hashBuffer.toString('hex');
};

userSchema.methods.checkPassword = function(password) {
  if (!this.passwordHash || !this.salt) return false;
  const iterations = this.pbkdf2Iterations || 120000;
  const keylen = this.pbkdf2Keylen || 64;
  const digest = this.pbkdf2Digest || 'sha512';

  const hashBuffer = crypto.pbkdf2Sync(password, this.salt, iterations, keylen, digest);
  const storedBuffer = Buffer.from(this.passwordHash, 'hex');

  // Длина должна совпадать, иначе timingSafeEqual выбросит
  if (storedBuffer.length !== hashBuffer.length) return false;
  return crypto.timingSafeEqual(storedBuffer, hashBuffer);
};

module.exports = mongoose.model('User', userSchema);
