const mongoose = require('mongoose');
const bcrypt = require('bcrypt');

const userSchema = new mongoose.Schema({
  username: {
    type: String,
    required: true,
    unique: true,
    trim: true,
    minlength: 3,
    maxlength: 30
  },
  passwordHash: {
    type: String,
    required: true
  },
  publicKey: {
    type: String,
    required: false // Will be set after key generation
  },
  keyAlgorithm: {
    type: String,
    enum: ['RSA-OAEP', 'RSASSA-PKCS1-v1_5', 'ECDH'],
    required: false
    // No default - field will be undefined until public key is set
  },
  createdAt: {
    type: Date,
    default: Date.now
  },
  lastLogin: {
    type: Date,
    default: null
  }
}, {
  timestamps: true
});

// Index for faster username lookups
userSchema.index({ username: 1 });

// Method to compare password (not stored in schema, used in routes)
userSchema.methods.comparePassword = async function(candidatePassword) {
  return await bcrypt.compare(candidatePassword, this.passwordHash);
};

const User = mongoose.model('User', userSchema);

module.exports = User;

