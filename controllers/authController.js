const User = require('../models/User');
const crypto = require('crypto');
const jwt = require('jsonwebtoken');
const nodemailer = require('nodemailer');
const { validationResult } = require('express-validator');

// Create email transporter
const createTransporter = () => {
  return nodemailer.createTransport({
    service: 'gmail',
    host: 'smtp.gmail.com',
    port: 587,
    secure: false,
    auth: {
      user: process.env.EMAIL_USER,
      pass: process.env.EMAIL_PASS
    }
  });
};

// Send email using Nodemailer
const sendEmail = async (to, subject, html) => {
  try {
    const transporter = createTransporter();
    
    const mailOptions = {
      from: process.env.EMAIL_FROM || `"LeafCare" <${process.env.EMAIL_USER}>`,
      to: to,
      subject: subject,
      html: html
    };

    const info = await transporter.sendMail(mailOptions);
    console.log('Email sent successfully:', info.messageId);
    return { success: true, messageId: info.messageId };
  } catch (error) {
    console.error('Email send error:', error);
    return { success: false, error: error.message };
  }
};

// Generate HTML response page
const generateResponsePage = (title, message, isSuccess, redirectUrl = null, redirectText = null) => {
  const statusColor = isSuccess ? '#4CAF50' : '#F44336';
  const statusIcon = isSuccess ? '✅' : '❌';
  
  return `
    <!DOCTYPE html>
    <html lang="en">
    <head>
      <meta charset="UTF-8">
      <meta name="viewport" content="width=device-width, initial-scale=1.0">
      <title>${title} - LeafCare</title>
      <style>
        * {
          margin: 0;
          padding: 0;
          box-sizing: border-box;
        }
        
        body {
          font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, Cantarell, sans-serif;
          background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
          min-height: 100vh;
          display: flex;
          align-items: center;
          justify-content: center;
          padding: 20px;
        }
        
        .container {
          background: white;
          border-radius: 12px;
          box-shadow: 0 20px 40px rgba(0,0,0,0.1);
          padding: 40px;
          text-align: center;
          max-width: 500px;
          width: 100%;
          animation: slideIn 0.5s ease-out;
        }
        
        @keyframes slideIn {
          from {
            opacity: 0;
            transform: translateY(-20px);
          }
          to {
            opacity: 1;
            transform: translateY(0);
          }
        }
        
        .icon {
          font-size: 64px;
          margin-bottom: 20px;
          color: ${statusColor};
        }
        
        .title {
          color: #333;
          font-size: 28px;
          font-weight: 600;
          margin-bottom: 16px;
        }
        
        .message {
          color: #666;
          font-size: 16px;
          line-height: 1.5;
          margin-bottom: 30px;
        }
        
        .button {
          display: inline-block;
          background: ${statusColor};
          color: white;
          padding: 12px 30px;
          text-decoration: none;
          border-radius: 6px;
          font-weight: 500;
          transition: all 0.3s ease;
          margin: 10px;
        }
        
        .button:hover {
          transform: translateY(-2px);
          box-shadow: 0 8px 20px rgba(0,0,0,0.2);
        }
        
        .secondary-button {
          background: #f5f5f5;
          color: #333;
        }
        
        .leafcare-logo {
          color: #4CAF50;
          font-weight: 700;
          font-size: 20px;
          margin-top: 30px;
          padding-top: 20px;
          border-top: 1px solid #eee;
        }
        
        .leafcare-logo::before {
          content: "🌿";
          margin-right: 8px;
        }
        
        @media (max-width: 480px) {
          .container {
            padding: 30px 20px;
          }
          
          .title {
            font-size: 24px;
          }
          
          .icon {
            font-size: 48px;
          }
        }
      </style>
    </head>
    <body>
      <div class="container">
        <div class="icon">${statusIcon}</div>
        <h1 class="title">${title}</h1>
        <p class="message">${message}</p>
        <div>
          ${redirectUrl ? `<a href="${redirectUrl}" class="button">${redirectText || 'Continue'}</a>` : ''}
          <button onclick="window.close()" class="button secondary-button">Close Window</button>
        </div>
        <div class="leafcare-logo">LeafCare</div>
      </div>
      
      ${redirectUrl ? `
      <script>
        // Auto redirect after 5 seconds if redirect URL is provided
        setTimeout(() => {
          window.location.href = '${redirectUrl}';
        }, 5000);
      </script>
      ` : ''}
    </body>
    </html>
  `;
};

// Send token response
const sendTokenResponse = (user, statusCode, res) => {
  // Create token
  const token = user.getSignedJwtToken();
  const refreshToken = user.getRefreshToken();

  // Parse the environment variable to an integer
  const cookieExpireDays = parseInt(process.env.JWT_COOKIE_EXPIRE, 10) || 30;

  const options = {
    // Correctly calculate the expiration date
    expires: new Date(Date.now() + cookieExpireDays * 24 * 60 * 60 * 1000),
    httpOnly: true
  };

  if (process.env.NODE_ENV === 'production') {
    options.secure = true;
  }

  // Update last login
  user.lastLogin = new Date();
  user.save({ validateBeforeSave: false });

  res
    .status(statusCode)
    .cookie('token', token, options)
    .json({
      success: true,
      token,
      refreshToken,
      user: {
        id: user._id,
        name: user.name,
        email: user.email,
        phone: user.phone,
        location: user.location,
        role: user.role,
        isVerified: user.isVerified,
        stats: user.stats,
        preferences: user.preferences,
        createdAt: user.createdAt
      }
    });
};

// @desc    Register user
// @route   POST /api/auth/register
// @access  Public
exports.register = async (req, res) => {
  try {
    // Check for validation errors
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({
        success: false,
        message: 'Validation failed',
        errors: errors.array()
      });
    }

    const { name, email, password, phone, location } = req.body;

    // Check if user already exists
    const existingUser = await User.findOne({ email });
    if (existingUser) {
      return res.status(400).json({
        success: false,
        message: 'User already exists with this email'
      });
    }

    // Create user
    const user = await User.create({
      name,
      email,
      password,
      phone,
      location
    });

    // Generate verification token (optional)
    const verificationToken = crypto.randomBytes(20).toString('hex');
    user.verificationToken = verificationToken;
    await user.save({ validateBeforeSave: false });

    // Send welcome email using Nodemailer
    if (process.env.EMAIL_USER) {
      const verificationUrl = `http://localhost:5000/api/auth/verify/${verificationToken}`;
      
      const welcomeEmailHtml = `
        <!DOCTYPE html>
        <html>
        <head>
          <meta charset="utf-8">
          <meta name="viewport" content="width=device-width, initial-scale=1">
          <title>Welcome to LeafCare</title>
          <style>
            body { font-family: Arial, sans-serif; line-height: 1.6; color: #333; max-width: 600px; margin: 0 auto; padding: 20px; }
            .header { background-color: #4CAF50; color: white; padding: 30px; text-align: center; border-radius: 8px 8px 0 0; }
            .content { background-color: #f9f9f9; padding: 30px; border-radius: 0 0 8px 8px; }
            .button { display: inline-block; background-color: #4CAF50; color: white; padding: 12px 30px; text-decoration: none; border-radius: 6px; font-weight: bold; margin: 20px 0; }
            .footer { text-align: center; margin-top: 20px; color: #666; font-size: 12px; }
          </style>
        </head>
        <body>
          <div class="header">
            <h1>🌿 Welcome to LeafCare!</h1>
          </div>
          <div class="content">
            <h2>Hello ${user.name}!</h2>
            <p>Thank you for joining our smart tomato farming community. LeafCare will help you:</p>
            <ul>
              <li>📱 Identify tomato diseases instantly</li>
              <li>📊 Track your farming progress</li>
              <li>🌱 Get personalized farming tips</li>
              <li>📰 Stay updated with agricultural news</li>
            </ul>
            <p>To complete your registration, please verify your email address:</p>
            <div style="text-align: center;">
              <a href="${verificationUrl}" class="button">Verify Email Address</a>
            </div>
            <p><strong>Note:</strong> If you didn't create this account, please ignore this email.</p>
            <p>Happy farming! 🍅</p>
          </div>
          <div class="footer">
            <p>© 2024 LeafCare - Smart Tomato Farming Solution</p>
          </div>
        </body>
        </html>
      `;

      await sendEmail(user.email, 'Welcome to LeafCare - Verify Your Email', welcomeEmailHtml);
    }

    sendTokenResponse(user, 201, res);
  } catch (error) {
    console.error('Registration error:', error);
    res.status(500).json({
      success: false,
      message: 'Server error during registration'
    });
  }
};

// @desc    Forgot password
// @route   POST /api/auth/forgotpassword
// @access  Public
exports.forgotPassword = async (req, res) => {
  try {
    const user = await User.findOne({ email: req.body.email });

    if (!user) {
      // Don't reveal that user doesn't exist
      return res.status(200).json({
        success: true,
        message: 'If an account with that email exists, a password reset link has been sent'
      });
    }

    // Get reset token
    const resetToken = user.getPasswordResetToken();
    await user.save({ validateBeforeSave: false });

    // Create reset url - point to backend endpoint
    const resetUrl = `http://localhost:5000/api/auth/reset-password-form/${resetToken}`;

    const resetEmailHtml = `
      <!DOCTYPE html>
      <html>
      <head>
        <meta charset="utf-8">
        <meta name="viewport" content="width=device-width, initial-scale=1">
        <title>Password Reset - LeafCare</title>
        <style>
          body { font-family: Arial, sans-serif; line-height: 1.6; color: #333; max-width: 600px; margin: 0 auto; padding: 20px; }
          .header { background-color: #FF6B35; color: white; padding: 30px; text-align: center; border-radius: 8px 8px 0 0; }
          .content { background-color: #f9f9f9; padding: 30px; border-radius: 0 0 8px 8px; }
          .button { display: inline-block; background-color: #FF6B35; color: white; padding: 12px 30px; text-decoration: none; border-radius: 6px; font-weight: bold; margin: 20px 0; }
          .warning { background-color: #fff3cd; border: 1px solid #ffeaa7; padding: 15px; border-radius: 4px; margin: 15px 0; }
          .footer { text-align: center; margin-top: 20px; color: #666; font-size: 12px; }
        </style>
      </head>
      <body>
        <div class="header">
          <h1>🔒 Password Reset Request</h1>
        </div>
        <div class="content">
          <h2>Hello ${user.name},</h2>
          <p>We received a request to reset your LeafCare account password.</p>
          <div class="warning">
            <strong>⚠️ This link expires in 10 minutes</strong>
          </div>
          <p>Click the button below to reset your password:</p>
          <div style="text-align: center;">
            <a href="${resetUrl}" class="button">Reset Password</a>
          </div>
          <p>If the button doesn't work, copy and paste this link into your browser:</p>
          <p style="word-break: break-all; background-color: #f0f0f0; padding: 10px; border-radius: 4px;">${resetUrl}</p>
          <p><strong>If you didn't request this reset, please ignore this email.</strong> Your password will remain unchanged.</p>
        </div>
        <div class="footer">
          <p>© 2024 LeafCare - Smart Tomato Farming Solution</p>
        </div>
      </body>
      </html>
    `;

    const emailResult = await sendEmail(user.email, 'LeafCare Password Reset Request', resetEmailHtml);

    if (!emailResult.success) {
      // Reset the fields if email fails
      user.passwordResetToken = undefined;
      user.passwordResetExpires = undefined;
      await user.save({ validateBeforeSave: false });

      return res.status(500).json({
        success: false,
        message: 'Email could not be sent'
      });
    }

    res.status(200).json({
      success: true,
      message: 'Password reset email sent'
    });
  } catch (error) {
    console.error('Forgot password error:', error);
    res.status(500).json({
      success: false,
      message: 'Server error'
    });
  }
};

// @desc    Show password reset form
// @route   GET /api/auth/reset-password-form/:resettoken
// @access  Public
exports.showResetPasswordForm = async (req, res) => {
  try {
    const resetPasswordToken = crypto
      .createHash('sha256')
      .update(req.params.resettoken)
      .digest('hex');

    const user = await User.findOne({
      passwordResetToken: resetPasswordToken,
      passwordResetExpires: { $gt: Date.now() }
    });

    if (!user) {
      const html = generateResponsePage(
        'Invalid Reset Link',
        'This password reset link is invalid or has expired. Please request a new password reset.',
        false
      );
      return res.status(400).send(html);
    }

    // Generate password reset form
    const resetForm = `
      <!DOCTYPE html>
      <html lang="en">
      <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Reset Password - LeafCare</title>
        <style>
          * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
          }
          
          body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, Cantarell, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
            display: flex;
            align-items: center;
            justify-content: center;
            padding: 20px;
          }
          
          .container {
            background: white;
            border-radius: 12px;
            box-shadow: 0 20px 40px rgba(0,0,0,0.1);
            padding: 40px;
            max-width: 400px;
            width: 100%;
            animation: slideIn 0.5s ease-out;
          }
          
          @keyframes slideIn {
            from {
              opacity: 0;
              transform: translateY(-20px);
            }
            to {
              opacity: 1;
              transform: translateY(0);
            }
          }
          
          .title {
            color: #333;
            font-size: 28px;
            font-weight: 600;
            margin-bottom: 8px;
            text-align: center;
          }
          
          .subtitle {
            color: #666;
            font-size: 14px;
            margin-bottom: 30px;
            text-align: center;
          }
          
          .form-group {
            margin-bottom: 20px;
          }
          
          label {
            display: block;
            color: #333;
            font-weight: 500;
            margin-bottom: 8px;
          }
          
          input[type="password"] {
            width: 100%;
            padding: 12px 16px;
            border: 2px solid #e1e5e9;
            border-radius: 8px;
            font-size: 16px;
            transition: border-color 0.3s ease;
          }
          
          input[type="password"]:focus {
            outline: none;
            border-color: #667eea;
          }
          
          .button {
            width: 100%;
            background: #667eea;
            color: white;
            padding: 12px;
            border: none;
            border-radius: 8px;
            font-size: 16px;
            font-weight: 600;
            cursor: pointer;
            transition: background 0.3s ease;
          }
          
          .button:hover {
            background: #5a67d8;
          }
          
          .button:disabled {
            background: #a0aec0;
            cursor: not-allowed;
          }
          
          .leafcare-logo {
            color: #4CAF50;
            font-weight: 700;
            font-size: 20px;
            margin-top: 30px;
            padding-top: 20px;
            border-top: 1px solid #eee;
            text-align: center;
          }
          
          .leafcare-logo::before {
            content: "🌿";
            margin-right: 8px;
          }
          
          .error {
            color: #e53e3e;
            font-size: 14px;
            margin-top: 5px;
          }
          
          .password-requirements {
            background: #f7fafc;
            border: 1px solid #e2e8f0;
            border-radius: 6px;
            padding: 12px;
            margin-top: 10px;
            font-size: 12px;
            color: #4a5568;
          }
        </style>
      </head>
      <body>
        <div class="container">
          <h1 class="title">Reset Password</h1>
          <p class="subtitle">Enter your new password below</p>
          
          <form id="resetForm" action="/api/auth/reset-password/${req.params.resettoken}" method="POST">
            <div class="form-group">
              <label for="password">New Password</label>
              <input type="password" id="password" name="password" required minlength="6">
              <div class="password-requirements">
                Password must be at least 6 characters long
              </div>
            </div>
            
            <div class="form-group">
              <label for="confirmPassword">Confirm New Password</label>
              <input type="password" id="confirmPassword" name="confirmPassword" required minlength="6">
              <div id="passwordError" class="error" style="display: none;"></div>
            </div>
            
            <button type="submit" class="button" id="submitBtn">Reset Password</button>
          </form>
          
          <div class="leafcare-logo">LeafCare</div>
        </div>
        
        <script>
          const form = document.getElementById('resetForm');
          const password = document.getElementById('password');
          const confirmPassword = document.getElementById('confirmPassword');
          const submitBtn = document.getElementById('submitBtn');
          const errorDiv = document.getElementById('passwordError');
          
          function validatePasswords() {
            if (password.value && confirmPassword.value) {
              if (password.value !== confirmPassword.value) {
                errorDiv.textContent = 'Passwords do not match';
                errorDiv.style.display = 'block';
                submitBtn.disabled = true;
                return false;
              } else {
                errorDiv.style.display = 'none';
                submitBtn.disabled = false;
                return true;
              }
            }
            return true;
          }
          
          password.addEventListener('input', validatePasswords);
          confirmPassword.addEventListener('input', validatePasswords);
          
          form.addEventListener('submit', function(e) {
            e.preventDefault();
            
            if (!validatePasswords() || password.value.length < 6) {
              return;
            }
            
            submitBtn.textContent = 'Resetting...';
            submitBtn.disabled = true;
            
            // Submit form
            const formData = new FormData();
            formData.append('password', password.value);
            
            fetch(form.action, {
              method: 'POST',
              headers: {
                'Content-Type': 'application/json',
              },
              body: JSON.stringify({ password: password.value })
            })
            .then(response => response.text())
            .then(html => {
              document.body.innerHTML = html;
            })
            .catch(error => {
              console.error('Error:', error);
              submitBtn.textContent = 'Reset Password';
              submitBtn.disabled = false;
              alert('An error occurred. Please try again.');
            });
          });
        </script>
      </body>
      </html>
    `;

    res.send(resetForm);
  } catch (error) {
    console.error('Show reset form error:', error);
    const html = generateResponsePage(
      'Server Error',
      'An error occurred while loading the password reset form. Please try again later.',
      false
    );
    res.status(500).send(html);
  }
};

// @desc    Handle password reset form submission
// @route   POST /api/auth/reset-password/:resettoken
// @access  Public
exports.resetPassword = async (req, res) => {
  try {
    const resetPasswordToken = crypto
      .createHash('sha256')
      .update(req.params.resettoken)
      .digest('hex');

    const user = await User.findOne({
      passwordResetToken: resetPasswordToken,
      passwordResetExpires: { $gt: Date.now() }
    });

    if (!user) {
      const html = generateResponsePage(
        'Invalid Reset Link',
        'This password reset link is invalid or has expired. Please request a new password reset.',
        false
      );
      return res.status(400).send(html);
    }

    user.password = req.body.password;
    user.passwordResetToken = undefined;
    user.passwordResetExpires = undefined;
    await user.save();

    const html = generateResponsePage(
      'Password Reset Successful!',
      'Your password has been reset successfully. You can now login to your LeafCare account with your new password.',
      true
    );
    
    res.status(200).send(html);
  } catch (error) {
    console.error('Reset password error:', error);
    const html = generateResponsePage(
      'Server Error',
      'An error occurred while resetting your password. Please try again later.',
      false
    );
    res.status(500).send(html);
  }
};

// @desc    Verify email
// @route   GET /api/auth/verify/:token
// @access  Public
exports.verifyEmail = async (req, res) => {
  try {
    const user = await User.findOne({ 
      verificationToken: req.params.token 
    });

    if (!user) {
      const html = generateResponsePage(
        'Invalid Verification Link',
        'This email verification link is invalid or has already been used. If you still need to verify your email, please contact support.',
        false
      );
      return res.status(400).send(html);
    }

    user.isVerified = true;
    user.verificationToken = undefined;
    await user.save({ validateBeforeSave: false });

    const html = generateResponsePage(
      'Email Verified Successfully!',
      `Welcome to LeafCare, ${user.name}! Your email has been verified successfully. You can now enjoy all features of the app.`,
      true
    );
    
    res.status(200).send(html);
  } catch (error) {
    console.error('Email verification error:', error);
    const html = generateResponsePage(
      'Server Error',
      'An error occurred while verifying your email. Please try again later.',
      false
    );
    res.status(500).send(html);
  }
};

// Keep all other existing methods unchanged
exports.login = async (req, res) => {
  try {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({
        success: false,
        message: 'Validation failed',
        errors: errors.array()
      });
    }

    const { email, password } = req.body;
    const user = await User.findOne({ email }).select('+password');

    if (!user) {
      return res.status(401).json({
        success: false,
        message: 'Invalid credentials'
      });
    }

    if (!user.isActive) {
      return res.status(401).json({
        success: false,
        message: 'Account has been deactivated'
      });
    }

    const isMatch = await user.matchPassword(password);
    if (!isMatch) {
      return res.status(401).json({
        success: false,
        message: 'Invalid credentials'
      });
    }

    sendTokenResponse(user, 200, res);
  } catch (error) {
    console.error('Login error:', error);
    res.status(500).json({
      success: false,
      message: 'Server error during login'
    });
  }
};

exports.getMe = async (req, res) => {
  try {
    const user = await User.findById(req.user.id);
    res.status(200).json({
      success: true,
      user
    });
  } catch (error) {
    console.error('Get user error:', error);
    res.status(500).json({
      success: false,
      message: 'Server error'
    });
  }
};

exports.updateProfile = async (req, res) => {
  try {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({
        success: false,
        message: 'Validation failed',
        errors: errors.array()
      });
    }

    const fieldsToUpdate = {
      name: req.body.name,
      phone: req.body.phone,
      location: req.body.location
    };

    Object.keys(fieldsToUpdate).forEach(key => {
      if (fieldsToUpdate[key] === undefined) {
        delete fieldsToUpdate[key];
      }
    });

    const user = await User.findByIdAndUpdate(
      req.user.id,
      fieldsToUpdate,
      {
        new: true,
        runValidators: true
      }
    );

    res.status(200).json({
      success: true,
      user
    });
  } catch (error) {
    console.error('Update profile error:', error);
    res.status(500).json({
      success: false,
      message: 'Server error updating profile'
    });
  }
};

exports.updatePassword = async (req, res) => {
  try {
    const user = await User.findById(req.user.id).select('+password');

    if (!(await user.matchPassword(req.body.currentPassword))) {
      return res.status(401).json({
        success: false,
        message: 'Current password is incorrect'
      });
    }

    user.password = req.body.newPassword;
    await user.save();

    sendTokenResponse(user, 200, res);
  } catch (error) {
    console.error('Update password error:', error);
    res.status(500).json({
      success: false,
      message: 'Server error updating password'
    });
  }
};

exports.logout = async (req, res) => {
  res.cookie('token', 'none', {
    expires: new Date(Date.now() + 10 * 1000),
    httpOnly: true
  });

  res.status(200).json({
    success: true,
    message: 'User logged out successfully'
  });
};

exports.refreshToken = async (req, res) => {
  try {
    const { refreshToken } = req.body;

    if (!refreshToken) {
      return res.status(401).json({
        success: false,
        message: 'Refresh token is required'
      });
    }

    const decoded = jwt.verify(refreshToken, process.env.JWT_REFRESH_SECRET);
    const user = await User.findById(decoded.id);

    if (!user || !user.isActive) {
      return res.status(401).json({
        success: false,
        message: 'Invalid refresh token'
      });
    }

    sendTokenResponse(user, 200, res);
  } catch (error) {
    console.error('Refresh token error:', error);
    res.status(401).json({
      success: false,
      message: 'Invalid refresh token'
    });
  }
};