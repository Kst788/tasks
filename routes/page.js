// routes/page.js
const express = require('express');
const router = express.Router();
const authenticate = require('../middleware/authMiddleware');
const db = require('../config/db');

router.get('/', (req, res) => {
  res.render('index');
});

router.get('/learn-more', (req, res) => {
  res.render('learnMore');
});

router.get('/features', (req, res) => {
  res.render('features');
});

router.get('/settings', authenticate, async (req, res) => {
  try {
    const user = await db.one('SELECT * FROM users WHERE id = $1', [req.user.id]);
    res.render('settings', { user });
  } catch (error) {
    console.error('Settings Error:', error.message);
    res.redirect('/');
  }
});

module.exports = router;
