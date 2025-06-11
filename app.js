const express = require('express');
const path = require('path');
require('dotenv').config();
const cookieParser = require('cookie-parser');
const cors = require('cors'); // 👈 Add this

const db = require('./config/db');
const taskRoutes = require('./routes/taskRoute');
const userRoutes = require('./routes/user');
const authRoutes = require('./routes/authRoute');
const pageRoutes = require('./routes/page');

const app = express();
const PORT = process.env.PORT || 3000;

// Trust proxy (important for HTTPS cookies on Render)
app.set('trust proxy', 1);

// CORS settings for cross-origin cookie support
app.use(cors({
  origin: 'https://your-frontend.onrender.com', // 👈 Replace with your frontend URL
  credentials: true, // ✅ Allow cookies to be sent
}));

// View engine and static files
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));
app.use(express.static(path.join(__dirname, 'public')));

// Middleware
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser());

// Routes
app.use('/', pageRoutes);
app.use('/auth', authRoutes);
app.use('/tasks', taskRoutes);
app.use('/api/users', userRoutes);

// DB test route
app.get('/db-test', async (req, res) => {
  try {
    await db.authenticate();
    res.send('Database connected successfully!');
  } catch (err) {
    res.status(500).send('Database connection failed: ' + err.message);
  }
});

// Start server
app.listen(PORT, () => {
  console.log(`Server running on http://localhost:${PORT}`);
});
