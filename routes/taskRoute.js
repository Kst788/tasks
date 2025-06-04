const express = require('express');
const router = express.Router();
const taskController = require('../controllers/taskController');
const authenticate = require('../middleware/authMiddleware'); // ✅ must import it

// ✅ apply middleware to protect all task routes
router.get('/', authenticate, taskController.getTasks);
router.post('/create', authenticate, taskController.createTask);
router.post('/update/:id', authenticate, taskController.updateTask);
router.get('/delete/:id', authenticate, taskController.deleteTask);

module.exports = router;
