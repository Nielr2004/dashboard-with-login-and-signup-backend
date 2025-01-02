const express = require('express');
const router = express.Router();
const User = require('../models/user');
const nodemailer = require('nodemailer');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');
const crypto = require('crypto');
const user = require('../models/user');
require('dotenv').config();

// Email transporter
const transporter = nodemailer.createTransport({
  service: 'Gmail',
  auth: {
    user: process.env.EMAIL_USER,
    pass: process.env.EMAIL_PASS,
  },
});

const verifyRole = (allowedRoles) => {
  return (req, res, next) => {
    const token = req.headers.authorization?.split(' ')[1];
    if (!token) return res.status(403).json({ message: 'No token provided' });

    try {
      const decoded = jwt.verify(token, process.env.JWT_SECRET);
      req.user = decoded;

      if (!allowedRoles.includes(decoded.role)) {
        return res.status(403).json({ message: 'Access denied' });
      }

      next();
    } catch (error) {
      res.status(401).json({ message: 'Invalid or expired token' });
    }
  };
};

// Sign up route
router.post('/signup', async (req, res) => {
  const { name, email, password, role } = req.body;
  try {
    const existingUser = await User.findOne({ email });
    if (existingUser) return res.status(400).json({ message: 'User already exists' });

    const hashedPassword = await bcrypt.hash(password, 10);

    const user = new User({
      name,
      email,
      password: hashedPassword,
      role: role || 'User', // Default role is 'User'
    });
    await user.save();

    const token = jwt.sign({ id: user._id, role: user.role }, process.env.JWT_SECRET, { expiresIn: '1h' });
    res.status(201).json({ token,name:name,role:user.role });
  } catch (error) {
    res.status(500).json({ message: 'Server error', error: error.message });
  }
});

// Sign in route
router.post('/signin', async (req, res) => {
  const { email, password } = req.body;
  try {
    const user = await User.findOne({ email });
    if (!user) return res.status(400).json({ message: 'User does not exist' });

    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) return res.status(400).json({ message: 'Invalid credentials' });

    const token = jwt.sign({ id: user._id, role: user.role }, process.env.JWT_SECRET, { expiresIn: '1h' });
    res.status(200).json({ token, email: email, role: user.role });
  } catch (error) {
    res.status(500).json({ message: 'Server error', error: error.message });
  }
});

// Protected route example (Super Admin only)
router.get('/super-admin', verifyRole(['Super Admin']),(req, res) => {
  
  res.status(200).json({ message: 'Welcome Super Admin!' });
});

// Protected route example (Admin onlu)
router.get('/admin', verifyRole(['Admin']), (req, res) => {
  res.status(200).json({ message: 'Welcome Admin or Super Admin!' });
});

// Send OTP route
router.post('/send-otp', async (req, res) => {
  const { email } = req.body;
  try {
    let user = await User.findOne({ email });
    if (!user) {
      user = new User({ email });
      await user.save();
    }

    const otp = crypto.randomInt(100000, 999999).toString();
    const otpExpires = Date.now() + 10 * 60 * 1000;

    user.otp = otp;
    user.otpExpires = otpExpires;
    await user.save();


    res.status(200).json({ message: 'OTP sent successfully!',otp:otp });
  } catch (error) {
    res.status(500).json({ message: 'Error sending OTP', error: error.message });
  }
});

// Verify OTP route
router.post('/verify-otp', async (req, res) => {
  const { email, otp } = req.body;
  try {
    const user = await User.findOne({ email });
    if (!user || user.otp !== otp || user.otpExpires < Date.now()) {
      return res.status(400).json({ message: 'Invalid or expired OTP' });
    }

    user.otp = null;
    user.otpExpires = null;
    await user.save();

    res.status(200).json({ message: 'OTP verified successfully!' });
  } catch (error) {
    res.status(500).json({ message: 'Error verifying OTP', error: error.message });
  }
});

// Update Profile route
router.put('/update-profile', async (req, res) => {
  const { email, name, password } = req.body;
  try {
    const user = await User.findOne({ email });
    if (!user) {
      return res.status(404).json({ message: 'User not found' });
    }

    user.name = name || user.name;
    if (password) {
      const salt = await bcrypt.genSalt(10);
      user.password = await bcrypt.hash(password, salt);
    }
    await user.save();

    res.status(200).json({ message: 'Profile updated successfully!' });
  } catch (error) {
    res.status(500).json({ message: 'Error updating profile', error: error.message });
  }
});

module.exports = router;