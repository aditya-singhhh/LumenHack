const express = require('express');
const router = express.Router();
const User = require('../Models/User');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const cookieParser = require('cookie-parser');
const authenticate = require('../Middlewares/Authenticate');

// Hardcoded secret and configurations (for local use)
const JWT_SECRET = '123';  // Replace with your own secret key for JWT
const JWT_EXPIRY = '1h';  // Token expiry duration
const COOKIE_MAX_AGE = 3600000;  // 1 hour in milliseconds

// Register a User
router.post('/register', async (req, res) => {
  try {
    const { name, email, password, role } = req.body;

    // Check if the user already exists
    const existingUser = await User.findOne({ email });
    if (existingUser) {
      return res.status(400).json({ message: 'User already exists' });
    }

    // Hash password
    const hashedPassword = await bcrypt.hash(password, 10);

    const newUser = new User({
      name,
      email,
      password: hashedPassword,
      role: role || 'Staff'  // Default role is 'Staff' if not provided
    });

    const savedUser = await newUser.save();

    res.status(201).json({ message: 'User registered successfully', user: savedUser });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Login a User
router.post('/login', async (req, res) => {
  try {
    const { email, password } = req.body;

    // Find the user by email
    const user = await User.findOne({ email });
    if (!user) {
      return res.status(400).json({ message: 'Invalid credentials' });
    }

    // Compare password
    const validPassword = await bcrypt.compare(password, user.password);
    if (!validPassword) {
      return res.status(400).json({ message: 'Invalid credentials' });
    }

    // Generate JWT token including userId and role
    const token = jwt.sign(
      { userId: user._id, role: user.role },  // Include role in JWT payload
      JWT_SECRET,  // Use hardcoded JWT_SECRET
      { expiresIn: JWT_EXPIRY }  // Token expiration time
    );

    // Set token as HttpOnly cookie
    res.cookie('token', token, {
      httpOnly: true,  // Ensures the cookie is sent only by HTTP(S) requests, not accessible by JS
      secure: false,   // Set to false for local testing (change to true in production)
      maxAge: COOKIE_MAX_AGE  // 1 hour (in milliseconds)
    });

    res.status(200).json({ message: 'Login successful' });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Get User Profile (protected)
router.get('/profile', authenticate, async (req, res) => {
  try {
    const user = await User.findById(req.userId);  // Use userId from the token
    res.status(200).json(user);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Admin Route - Only accessible by Admin
router.get('/admin-dashboard', authenticate, (req, res) => {
  if (req.user.role !== 'Admin') {
    return res.status(403).json({ message: 'Access forbidden: Admins only' });
  }
  res.status(200).json({ message: 'Welcome to the Admin Dashboard.' });
});

// Manager Route - Accessible by Admin and Manager
router.get('/manager-dashboard', authenticate, (req, res) => {
  if (!['Admin', 'Manager'].includes(req.user.role)) {
    return res.status(403).json({ message: 'Access forbidden: Admins and Managers only' });
  }
  res.status(200).json({ message: 'Welcome to the Manager Dashboard.' });
});

// Staff Route - Accessible by Admin, Manager, and Staff
router.get('/staff-dashboard', authenticate, (req, res) => {
  if (!['Admin', 'Manager', 'Staff'].includes(req.user.role)) {
    return res.status(403).json({ message: 'Access forbidden: Admins, Managers, and Staff only' });
  }
  res.status(200).json({ message: 'Welcome to the Staff Dashboard.' });
});

// Logout Route (clear the token cookie)
router.post('/logout', authenticate, (req, res) => {
  res.clearCookie('token');  // Clear the token cookie
  res.status(200).json({ message: 'Logged out successfully' });
});

module.exports = router;
