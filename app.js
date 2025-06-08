const express = require('express');
const path = require('path');
require('dotenv').config();
const cookieParser = require('cookie-parser');

const db = require('./config/db');
const initializeDatabase = require('./config/init-db');
const taskRoutes = require('./routes/taskRoute');
const userRoutes = require('./routes/user');
const authRoutes = require('./routes/authRoute');
const pageRoutes = require('./routes/page'); // ✅ handles /features, /learn-more etc.

const app = express();
const PORT = process.env.PORT || 3000;

// View engine and static files
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));
app.use(express.static(path.join(__dirname, 'public')));

// Middleware
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser());

// Routes
app.use('/', pageRoutes);             // ✅ Landing, features, learn-more, etc.
app.use('/auth', authRoutes);         // ✅ Auth routes
app.use('/tasks', taskRoutes);        // ✅ Task management
app.use('/api/users', userRoutes);    // ✅ Optional: for API

// Initialize database and start server
(async () => {
  try {
    // Initialize database tables
    await initializeDatabase();
    console.log('Database initialized successfully');

    // Start server
    app.listen(PORT, () => {
      console.log(`Server running on http://localhost:${PORT}`);
    });
  } catch (error) {
    console.error('Failed to initialize application:', error);
    process.exit(1);
  }
})();
