// config/db.js
const pgp = require('pg-promise')();
require('dotenv').config();

const db = pgp({
  host: process.env.DB_HOST,
  port: 5432, // your PostgreSQL port
  database: process.env.DB_NAME,
  user: process.env.DB_USER,
  password: process.env.DB_PASS,
  //ssl: {
    //rejectUnauthorized: false // Adjust SSL in settings as necessary
  //}
});

module.exports = db;  