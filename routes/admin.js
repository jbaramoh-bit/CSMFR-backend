const express = require('express');
const router = express.Router();
const db = require('../db');
const auth = require('../auth');
const bcrypt = require('bcrypt');

// GET all users (admin only)
router.get('/users', auth.authenticate, auth.authorize(['admin']), async (req, res) => {
    try {
        const { rows } = await db.query(`
            SELECT
                u.id,
                u.username,
                u.role,
                u.full_name,
                u.phone_number,
                u.status,
                u.last_login,
                u.group_id,
                sg.name AS group_name
            FROM
                users u
            LEFT JOIN
                security_groups sg ON u.group_id = sg.id
            ORDER BY u.id ASC
        `);
        res.json(rows);
    } catch (err) {
        console.error(err.message);
        res.status(500).send('Server error');
    }
});

// UPDATE user information (admin only)
router.put('/users/:id', auth.authenticate, auth.authorize(['admin']), async (req, res) => {
    try {
        const { id } = req.params;
        const { full_name, username, phone_number, role, status } = req.body;

        // validation
        if (role && !['user', 'admin'].includes(role)) {
            return res.status(400).json({ msg: 'Invalid role provided.' });
        }
        if (status && !['active', 'inactive'].includes(status)) {
            return res.status(400).json({ msg: 'Invalid status provided.' });
        }

        const { rows } = await db.query(
            'UPDATE users SET full_name = $1, username = $2, phone_number = $3, role = $4, status = $5 WHERE id = $6 RETURNING id, username, role, full_name, phone_number, status',
            [full_name, username, phone_number, role, status, id]
        );

        if (rows.length === 0) {
            return res.status(404).json({ msg: 'User not found' });
        }

        res.json(rows[0]);
    } catch (err) {
        console.error(err.message);
        res.status(500).send('Server error');
    }
});

// UPDATE user status (admin only)
router.put('/users/:id/status', auth.authenticate, auth.authorize(['admin']), async (req, res) => {
    try {
        const { id } = req.params;
        const { status } = req.body;

        // Basic validation for status
        if (!status || !['active', 'inactive'].includes(status)) {
            return res.status(400).json({ msg: 'Invalid status provided.' });
        }

        const { rows } = await db.query(
            'UPDATE users SET status = $1 WHERE id = $2 RETURNING id, username, status',
            [status, id]
        );

        if (rows.length === 0) {
            return res.status(404).json({ msg: 'User not found' });
        }

        res.json(rows[0]);
    } catch (err) {
        console.error(err.message);
        res.status(500).send('Server error');
    }
});


// SET user password (admin only)
router.post('/users/:id/set-password', auth.authenticate, auth.authorize(['admin']), async (req, res) => {
    try {
        const { id } = req.params;
        const { password } = req.body;

        if (!password) {
            return res.status(400).json({ msg: 'Password is required.' });
        }

        const saltRounds = 10;
        const hashedPassword = await bcrypt.hash(password, saltRounds);

        const { rows } = await db.query(
            'UPDATE users SET password = $1 WHERE id = $2 RETURNING id, username',
            [hashedPassword, id]
        );

        if (rows.length === 0) {
            return res.status(404).json({ msg: 'User not found' });
        }

        res.json({ msg: `Password for user ${rows[0].username} has been updated.` });
    } catch (err) {
        console.error(err.message);
        res.status(500).send('Server error');
    }
});


module.exports = router;