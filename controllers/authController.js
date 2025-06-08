const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const crypto = require('crypto');
const db = require('../config/db');
const sendEmail = require('../utils/sendEmail');

// GET: Signup Page
exports.getSignup = (req, res) => {
  res.render('signup');
};

// POST: Signup Handler
exports.postSignup = async (req, res) => {
  const { name, email, password } = req.body;
  try {
    // Check for existing user first
    const existingUser = await db.oneOrNone('SELECT * FROM users WHERE email = $1', [email]);
    if (existingUser) {
      if (!existingUser.is_verified) {
        // User exists but isn't verified - offer to resend verification
        return res.render('verificationMessage', { 
          email,
          error: 'This email is already registered but not verified.',
          showResend: true
        });
      } else {
        // User exists and is verified - suggest login
        return res.render('signup', {
          error: 'This email is already registered. Please log in instead.',
          values: { name, email }
        });
      }
    }

    const hashedPassword = await bcrypt.hash(password, 10);
    const verificationToken = crypto.randomBytes(32).toString('hex');

    await db.none(
      `INSERT INTO users (name, email, password, is_verified, verification_token)
       VALUES ($1, $2, $3, $4, $5)`,
      [name, email, hashedPassword, false, verificationToken]
    );

    // Ensure proper URL construction for verification
    const baseUrl = process.env.BASE_URL || `${req.protocol}://${req.get('host')}`;
    // Make sure there's no double slashes in the URL
    const verifyUrl = `${baseUrl.replace(/\/$/, '')}/auth/verify-email?token=${encodeURIComponent(verificationToken)}&email=${encodeURIComponent(email)}`;
    
    // Send a more detailed email with troubleshooting instructions
    await sendEmail({
      to: email,
      subject: 'Verify Your Email - MyTask',
      html: `
        <!DOCTYPE html>
        <html>
        <head>
          <style>
            .container { font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto; padding: 20px; }
            .button { display: inline-block; padding: 12px 24px; background-color: #4CAF50; color: white; text-decoration: none; border-radius: 5px; margin: 20px 0; }
            .note { font-size: 0.9em; color: #666; margin-top: 20px; }
            .help { background-color: #f8f9fa; padding: 15px; border-radius: 5px; margin-top: 20px; }
          </style>
        </head>
        <body>
          <div class="container">
            <h1>Welcome to MyTask!</h1>
            <p>Hello ${name},</p>
            <p>Thank you for signing up. Please verify your email address to activate your account.</p>
            
            <a href="${verifyUrl}" class="button">Verify Email Address</a>
            
            <div class="note">
              <p>If the button above doesn't work, you can copy and paste this link into your browser:</p>
              <p>${verifyUrl}</p>
            </div>
            
            <div class="help">
              <p><strong>Having trouble?</strong></p>
              <ul>
                <li>Make sure you're clicking the link from the same device you signed up on</li>
                <li>Try copying and pasting the link directly into your browser</li>
                <li>If the link expires, you can request a new one from the login page</li>
                <li>Check if your email client is modifying the link</li>
              </ul>
            </div>
            
            <p>This verification link will expire in 24 hours for security reasons.</p>
            <p>If you didn't create an account with MyTask, you can safely ignore this email.</p>
          </div>
        </body>
        </html>
      `
    });

    res.render('verificationMessage', { email });
  } catch (err) {
    console.error('Signup Error:', err.message);
    
    // Handle specific database errors
    if (err.code === '23505' && err.constraint === 'users_email_key') {
      // Race condition: Another signup with same email happened between our check and insert
      return res.render('signup', {
        error: 'This email address is already registered. Please try logging in or use a different email.',
        values: { name, email }
      });
    }
    
    res.render('signup', {
      error: 'An error occurred during signup. Please try again.',
      values: { name, email }
    });
  }
};

// GET: Email Verification
exports.verifyEmail = async (req, res) => {
  const { token, email } = req.query;
  
  if (!token || !email) {
    return res.status(400).render('error', {
      error: 'Invalid verification link. Please request a new one.',
      email
    });
  }

  try {
    // Log verification attempt for debugging
    console.log('Verification attempt:', { email, token: token.substring(0, 10) + '...' });

    const user = await db.oneOrNone('SELECT * FROM users WHERE email = $1 AND verification_token = $2', [email, token]);
    
    if (!user) {
      console.log('Verification failed: User not found or token mismatch');
      return res.status(400).render('error', {
        error: 'Invalid or expired verification token. Please request a new one.',
        email
      });
    }

    if (user.is_verified) {
      console.log('User already verified:', email);
      return res.render('successfulVerification', { 
        name: user.name,
        alreadyVerified: true
      });
    }

    await db.none('UPDATE users SET is_verified = true, verification_token = NULL WHERE email = $1', [email]);
    console.log('User successfully verified:', email);
    
    res.render('successfulVerification', { name: user.name });
  } catch (err) {
    console.error('Verify Email Error:', err);
    res.status(500).render('error', {
      error: 'Server error during email verification. Please try again.',
      email,
      details: process.env.NODE_ENV === 'development' ? err.message : undefined
    });
  }
};

// POST: Resend Verification Email
exports.resendVerification = async (req, res) => {
  const { email } = req.body;
  try {
    const user = await db.oneOrNone('SELECT * FROM users WHERE email = $1 AND is_verified = false', [email]);
    if (!user) {
      return res.status(400).json({
        error: 'No unverified user found with this email.'
      });
    }

    const verificationToken = crypto.randomBytes(32).toString('hex');
    await db.none('UPDATE users SET verification_token = $1 WHERE email = $2', [verificationToken, email]);

    const baseUrl = process.env.BASE_URL || `${req.protocol}://${req.get('host')}`;
    const verifyUrl = `${baseUrl}/auth/verify-email?token=${verificationToken}&email=${encodeURIComponent(email)}`;
    
    await sendEmail({
      to: email,
      subject: 'Verify Your Email',
      html: `
        <h1>MyTask Email Verification</h1>
        <p>Hello ${user.name},</p>
        <p>Here's your new verification link:</p>
        <a href="${verifyUrl}" style="display: inline-block; padding: 10px 20px; background-color: #4CAF50; color: white; text-decoration: none; border-radius: 5px;">Verify Email</a>
        <p>If the button doesn't work, you can copy and paste this link into your browser:</p>
        <p>${verifyUrl}</p>
        <p>This link will expire in 24 hours.</p>
      `
    });

    res.json({ message: 'Verification email resent successfully.' });
  } catch (err) {
    console.error('Resend Verification Error:', err.message);
    res.status(500).json({
      error: 'Server error while resending verification email.'
    });
  }
};

// GET: Login Page
exports.getLogin = (req, res) => {
  res.render('login');
};

// POST: Login Handler
exports.postLogin = async (req, res) => {
  const { email, password } = req.body;
  try {
    const user = await db.oneOrNone('SELECT * FROM users WHERE email = $1', [email]);
    if (!user) return res.status(401).send('User not found.');

    if (!user.is_verified) {
      return res.status(401).send('Please verify your email before logging in.');
    }

    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) return res.status(401).send('Invalid credentials.');

    const token = jwt.sign({ id: user.id, email: user.email }, process.env.JWT_SECRET, { expiresIn: '1h' });
    res.cookie('token', token, { httpOnly: true });
    res.redirect('/tasks');
  } catch (err) {
    console.error('Login Error:', err.message);
    res.status(500).send('Server error during login.');
  }
};

// GET: Logout
exports.logout = (req, res) => {
  res.clearCookie('token');
  res.redirect('/');
};

// GET: Forgot Password Page
exports.getForgotPassword = (req, res) => {
  res.render('forgotPassword');
};

// POST: Forgot Password Handler
exports.postForgotPassword = async (req, res) => {
  const { email } = req.body;
  try {
    const user = await db.oneOrNone('SELECT * FROM users WHERE email = $1', [email]);
    if (!user) return res.status(400).send('No account with that email.');

    const resetToken = crypto.randomBytes(32).toString('hex');
    const resetExpires = new Date(Date.now() + 60 * 60 * 1000); // 1 hour

    await db.none(
      'UPDATE users SET reset_password_token = $1, reset_password_expires = $2 WHERE email = $3',
      [resetToken, resetExpires, email]
    );

    const resetUrl = `${req.protocol}://${req.get('host')}/auth/reset-password/${resetToken}`;
    await sendEmail(email, 'Password Reset', `
      <p>You requested a password reset.</p>
      <p>Click the link below to reset your password (valid for 1 hour):</p>
      <a href="${resetUrl}">Reset Password</a>
    `);

    res.send('Password reset email sent. Please check your inbox.');
  } catch (err) {
    console.error('Forgot Password Error:', err.message);
    res.status(500).send('Server error during password reset.');
  }
};

// GET: Reset Password Page
exports.getResetPassword = async (req, res) => {
  const { token } = req.params;
  try {
    const user = await db.oneOrNone(
      'SELECT * FROM users WHERE reset_password_token = $1 AND reset_password_expires > NOW()',
      [token]
    );
    if (!user) return res.status(400).send('Invalid or expired token.');
    res.render('resetPassword', { token });
  } catch (err) {
    console.error('Get Reset Password Error:', err.message);
    res.status(500).send('Server error loading reset page.');
  }
};

// POST: Reset Password Handler
exports.postResetPassword = async (req, res) => {
  const { token } = req.params;
  const { password } = req.body;
  try {
    const user = await db.oneOrNone(
      'SELECT * FROM users WHERE reset_password_token = $1 AND reset_password_expires > NOW()',
      [token]
    );
    if (!user) return res.status(400).send('Invalid or expired token.');

    const hashedPassword = await bcrypt.hash(password, 10);

    await db.none(
      'UPDATE users SET password = $1, reset_password_token = NULL, reset_password_expires = NULL WHERE id = $2',
      [hashedPassword, user.id]
    );

    res.send('Password reset successful. You can now log in.');
  } catch (err) {
    console.error('Reset Password Error:', err.message);
    res.status(500).send('Server error resetting password.');
  }
};
