// config/db.js
const pgp = require('pg-promise')();
require('dotenv').config();

const db = pgp({
  host: process.env.DB_HOST,
  port: 5432, // your PostgreSQL port
  database: process.env.DB_NAME,
  user: process.env.DB_USER,
  password: process.env.DB_PASS,
  ssl: {
    rejectUnauthorized: false // Adjust SSL in settings as necessary
  }
});

// Function to initialize database schema
const initializeSchema = async () => {
  try {
    // Create Users table
    await db.none(`
      CREATE TABLE IF NOT EXISTS "Users" (
        id SERIAL PRIMARY KEY,
        email VARCHAR(255) UNIQUE NOT NULL,
        password VARCHAR(255) NOT NULL,
        "isVerified" BOOLEAN DEFAULT FALSE,
        "verificationToken" VARCHAR(255),
        "resetPasswordToken" VARCHAR(255),
        "resetPasswordExpires" TIMESTAMP,
        "createdAt" TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        "updatedAt" TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      );
    `);

    // Create Tasks table
    await db.none(`
      CREATE TABLE IF NOT EXISTS "tasks" (
        id SERIAL PRIMARY KEY,
        user_id INTEGER REFERENCES "Users"(id) ON DELETE CASCADE,
        title VARCHAR(255) NOT NULL,
        description TEXT,
        completed BOOLEAN DEFAULT FALSE,
        status VARCHAR(50) DEFAULT 'pending',
        due_date TIMESTAMP,
        "createdAt" TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        "updatedAt" TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      );
    `);

    // Create indexes
    await db.none(`
      CREATE INDEX IF NOT EXISTS idx_tasks_user_id ON tasks(user_id);
      CREATE INDEX IF NOT EXISTS idx_users_email ON "Users"(email);
    `);

    console.log('Database schema initialized successfully');
  } catch (error) {
    console.error('Error initializing database schema:', error);
    throw error;
  }
};

// Initialize schema when the application starts
initializeSchema().catch(console.error);

module.exports = db;