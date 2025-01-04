const mongoose = require('mongoose');

const userSchema = new mongoose.Schema({
  name: {
    type: String,
    required: true,
    trim: true
  },
  email: {
    type: String,
    required: true,
    unique: true,
    trim: true,
    lowercase: true
  },
  password: {
    type: String,
    required: true
  },
  role: {
    type: String,
    enum: ['Admin', 'Manager', 'Staff'],  // Define possible roles
    default: 'Staff'  // Default role is 'Staff' if not provided
  }
}, {
  timestamps: true  // Optional, to track when users are created/updated
});

module.exports = mongoose.model('User', userSchema);
