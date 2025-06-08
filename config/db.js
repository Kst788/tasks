// config/db.js
const pgp = require('pg-promise')();
require('dotenv').config();

const isProduction = process.env.NODE_ENV === 'production';

const db = pgp({
  host: process.env.DB_HOST,
  port: process.env.DB_PORT || 5432,
  database: process.env.DB_NAME,
  user: process.env.DB_USER,
  password: process.env.DB_PASS,
  ssl: isProduction ? {
    rejectUnauthorized: false,
    sslmode: 'require'
  } : false
});

// Test database connection
db.connect()
  .then(obj => {
    console.log('Database connection successful');
    obj.done(); // success, release the connection;
  })
  .catch(error => {
    console.error('Database connection error:', error.message);
  });

module.exports = db;