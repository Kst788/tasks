const db = require('../config/db');

// Fetch all tasks for the logged-in user
exports.getTasks = async (req, res) => {
  try {
    const userId = req.user.id;
    const tasks = await db.any('SELECT * FROM tasks WHERE user_id = $1 ORDER BY due_date ASC NULLS LAST', [userId]);

    res.render('dashboard', {
      tasks,
      userEmail: req.user.email
    });
  } catch (error) {
    console.error('Get Tasks Error:', error.message);
    res.status(500).send('Failed to fetch tasks');
  }
};

// Create a new task for the logged-in user
exports.createTask = async (req, res) => {
  try {
    const userId = req.user.id;
    const { title, description, dueDate, dueTime, status } = req.body;

    // Combine date & time if both provided
    let dueDateTime = null;
    if (dueDate && dueTime) {
      dueDateTime = new Date(`${dueDate}T${dueTime}`);
    } else if (dueDate) {
      dueDateTime = new Date(dueDate);
    }

    const finalStatus = status || 'pending';

    await db.none(
      'INSERT INTO tasks (title, description, due_date, status, user_id) VALUES ($1, $2, $3, $4, $5)',
      [title.trim(), description?.trim() || null, dueDateTime, finalStatus, userId]
    );

    res.redirect('/tasks');
  } catch (error) {
    console.error('Create Task Error:', error.message);
    res.status(500).send('Failed to create task');
  }
};

// Update an existing task
exports.updateTask = async (req, res) => {
  try {
    const taskId = req.params.id;
    const { title, description, dueDate, dueTime, status } = req.body;

    // Combine date & time if both provided
    let dueDateTime = null;
    if (dueDate && dueTime) {
      dueDateTime = new Date(`${dueDate}T${dueTime}`);
    } else if (dueDate) {
      dueDateTime = new Date(dueDate);
    }

    await db.none(
      'UPDATE tasks SET title = $1, description = $2, due_date = $3, status = $4 WHERE id = $5',
      [title.trim(), description?.trim() || null, dueDateTime, status, taskId]
    );

    res.redirect('/tasks');
  } catch (error) {
    console.error('Update Task Error:', error.message);
    res.status(500).send('Failed to update task');
  }
};

// Delete a task
exports.deleteTask = async (req, res) => {
  try {
    const taskId = req.params.id;
    await db.none('DELETE FROM tasks WHERE id = $1', [taskId]);
    res.redirect('/tasks');
  } catch (error) {
    console.error('Delete Task Error:', error.message);
    res.status(500).send('Failed to delete task');
  }
};
