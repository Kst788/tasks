const db = require('../config/db');

// Fetch all tasks for the logged-in user
exports.getTasks = async (req, res) => {
  try {
    const userId = req.user.id;
    const tasks = await db.any('SELECT * FROM tasks WHERE user_id = $1 ORDER BY due_date ASC NULLS LAST', [userId]);

    res.render('dashboard', {
      tasks,
      userEmail: req.user.email,
      path: '/tasks'
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

    // Improved date & time handling
    let dueDateTime = null;
    if (dueDate) {
      try {
        if (dueTime) {
          // Make sure we have valid date and time values
          const dateTimeString = `${dueDate}T${dueTime}`;
          const parsedDate = new Date(dateTimeString);
          if (!isNaN(parsedDate.getTime())) {
            dueDateTime = parsedDate;
          }
        } else {
          // Handle date only
          const parsedDate = new Date(dueDate);
          if (!isNaN(parsedDate.getTime())) {
            dueDateTime = parsedDate;
          }
        }
      } catch (dateError) {
        console.error('Date parsing error:', dateError);
        // Continue with null dueDateTime if date parsing fails
      }
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

// Get task for editing
exports.getEditTask = async (req, res) => {
  try {
    const taskId = req.params.id;
    const userId = req.user.id;

    const task = await db.oneOrNone(
      'SELECT * FROM tasks WHERE id = $1 AND user_id = $2',
      [taskId, userId]
    );

    if (!task) {
      return res.status(404).send('Task not found');
    }

    // Format the date and time for the form
    let dateValue = '';
    let timeValue = '';
    if (task.due_date) {
      const dueDate = new Date(task.due_date);
      dateValue = dueDate.toISOString().split('T')[0];
      timeValue = dueDate.toTimeString().split(' ')[0].slice(0, 5);
    }

    res.render('editTask', {
      task,
      dateValue,
      timeValue,
      userEmail: req.user.email,
      path: '/tasks/edit'
    });
  } catch (error) {
    console.error('Get Edit Task Error:', error.message);
    res.status(500).send('Failed to get task for editing');
  }
};
