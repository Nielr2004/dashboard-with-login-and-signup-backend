const mongoose = require('mongoose');

const UserSchema = new mongoose.Schema({
  name: { type: String, default: '' },
  email: { type: String, required: true, unique: true },
  password: { type: String,required:true },
  role: {
    type: String,
    enum: ['Super Admin', 'Admin', 'User'],
    default: 'User', 
  },
  otp: { type: String },
  otpExpires: { type: Date },
});

module.exports = mongoose.model('User', UserSchema);