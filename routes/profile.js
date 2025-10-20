const express = require('express');
const router = express.Router();
const db = require('../db');
const bcrypt = require('bcrypt');

// Get user profile
router.get('/', async (req, res) => {
    try {
        const { rows } = await db.query('SELECT id, username, full_name, phone_number, profile_picture_url, role, two_factor_auth_enabled, interface_language, date_format, number_format, email_notifications, last_login FROM users WHERE id = $1', [req.user.id]);
        if (rows.length === 0) {
            return res.status(404).json({ msg: 'User not found' });
        }
        res.json(rows[0]);
    } catch (err) {
        console.error(err.message);
        res.status(500).send('Server error');
    }
});

// Update user profile
router.put('/', async (req, res) => {
    try {
        const { full_name, phone_number, profile_picture_url, interface_language, date_format, number_format, email_notifications } = req.body;
        const updatedUser = await db.query(
            'UPDATE users SET full_name = $1, phone_number = $2, profile_picture_url = $3, interface_language = $4, date_format = $5, number_format = $6, email_notifications = $7 WHERE id = $8 RETURNING *',
            [full_name, phone_number, profile_picture_url, interface_language, date_format, number_format, email_notifications, req.user.id]
        );
        res.json(updatedUser.rows[0]);
    } catch (err) {
        console.error(err.message);
        res.status(500).send('Server error');
    }
});

// Change password
router.post('/change-password', async (req, res) => {
    const { currentPassword, newPassword } = req.body;
    try {
        const { rows } = await db.query('SELECT password FROM users WHERE id = $1', [req.user.id]);
        const user = rows[0];
        const match = await bcrypt.compare(currentPassword, user.password);
        if (!match) {
            return res.status(400).json({ msg: 'Incorrect current password' });
        }
        const salt = await bcrypt.genSalt(10);
        const hashedPassword = await bcrypt.hash(newPassword, salt);
        await db.query('UPDATE users SET password = $1 WHERE id = $2', [hashedPassword, req.user.id]);
        res.json({ msg: 'Password updated successfully' });
    } catch (err) {
        console.error(err.message);
        res.status(500).send('Server error');
    }
});

// Toggle 2FA
router.post('/toggle-2fa', async (req, res) => {
    const { enable } = req.body;
    try {
        await db.query('UPDATE users SET two_factor_auth_enabled = $1 WHERE id = $2', [enable, req.user.id]);
        res.json({ msg: `Two-factor authentication ${enable ? 'enabled' : 'disabled'}` });
    } catch (err) {
        console.error(err.message);
        res.status(500).send('Server error');
    }
});

// Get active sessions (placeholder)
router.get('/sessions', (req, res) => {
    res.json([]);
});

// Logout from a session (placeholder)
router.post('/logout-session/:sessionId', (req, res) => {
    res.json({ msg: 'Session logged out' });
});

// Get recent activity (placeholder)
router.get('/activity', (req, res) => {
    res.json([]);
});

module.exports = router;
