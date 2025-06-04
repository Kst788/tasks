// models/userModel.js
const db = require('../config/db');

const User = {
  async create({ email, password, verificationToken }) {
    const query = `
      INSERT INTO "Users" (email, password, "isVerified", "verificationToken")
      VALUES ($1, $2, $3, $4)
      RETURNING *;
    `;
    return db.one(query, [email, password, false, verificationToken]);
  },

  async findByEmail(email) {
    const query = `SELECT * FROM "Users" WHERE email = $1;`;
    return db.oneOrNone(query, [email]);
  },

  async findByEmailAndToken(email, token) {
    const query = `SELECT * FROM "Users" WHERE email = $1 AND "verificationToken" = $2;`;
    return db.oneOrNone(query, [email, token]);
  },

  async verifyUser(email) {
    const query = `UPDATE "Users" SET "isVerified" = true, "verificationToken" = NULL WHERE email = $1 RETURNING *;`;
    return db.one(query, [email]);
  },

  async setResetToken(email, resetToken, resetExpires) {
    const query = `
      UPDATE "Users"
      SET "resetPasswordToken" = $2, "resetPasswordExpires" = $3
      WHERE email = $1 RETURNING *;
    `;
    return db.oneOrNone(query, [email, resetToken, resetExpires]);
  },

  async findByResetToken(token) {
    const query = `
      SELECT * FROM "Users"
      WHERE "resetPasswordToken" = $1 AND "resetPasswordExpires" > NOW();
    `;
    return db.oneOrNone(query, [token]);
  },

  async updatePassword(id, hashedPassword) {
    const query = `
      UPDATE "Users"
      SET password = $2, "resetPasswordToken" = NULL, "resetPasswordExpires" = NULL
      WHERE id = $1 RETURNING *;
    `;
    return db.one(query, [id, hashedPassword]);
  },
};

module.exports = User;
