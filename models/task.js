const db = require('../config/db');

const Task = {
  async createTask({ userId, title, description }) {
    const result = await db.one(
      `INSERT INTO tasks (user_id, title, description, completed)
       VALUES ($1, $2, $3, false)
       RETURNING *`,
      [userId, title, description]
    );
    return result;
  },

  async getTasksByUser(userId) {
    return await db.any(
      `SELECT * FROM tasks WHERE user_id = $1`,
      [userId]
    );
  },

  async getTaskById(id) {
    return await db.oneOrNone(`SELECT * FROM tasks WHERE id = $1`, [id]);
  },

  async updateTask(id, { title, description, completed }) {
    return await db.oneOrNone(
      `UPDATE tasks
       SET title = $1, description = $2, completed = $3
       WHERE id = $4
       RETURNING *`,
      [title, description, completed, id]
    );
  },

  async deleteTask(id) {
    return await db.result(`DELETE FROM tasks WHERE id = $1`, [id]);
  },
};

module.exports = Task;
