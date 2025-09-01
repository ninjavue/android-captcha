const express = require('express');
const router = express.Router();
const { changePassword } = require('../controllers/settings');
const { requireAuth } = require('../controllers/auth');

router.post('/change-password', requireAuth, changePassword);

module.exports = router;