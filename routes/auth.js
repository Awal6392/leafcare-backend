const express = require('express');
const {
  register,
  login,
  getMe,
  updateProfile,
  updatePassword,
  forgotPassword,
  resetPassword,
  logout,
  refreshToken,
  verifyEmail
} = require('../controllers/authController');
const { protect } = require('../middleware/auth');
const {
  validateRegister,
  validateLogin,
  validateProfileUpdate,
  validatePasswordUpdate,
  validatePasswordReset,
  validateEmail
} = require('../middleware/validation');

const router = express.Router();

// Public routes
router.post('/register', validateRegister, register);
router.post('/login', validateLogin, login);
router.post('/forgotpassword', validateEmail, forgotPassword);
router.put('/resetpassword/:resettoken', validatePasswordReset, resetPassword);
router.post('/refresh', refreshToken);
router.get('/verify/:token', verifyEmail);

// Protected routes
router.get('/me', protect, getMe);
router.put('/profile', protect, validateProfileUpdate, updateProfile);
router.put('/updatepassword', protect, validatePasswordUpdate, updatePassword);
router.get('/logout', protect, logout);

module.exports = router;