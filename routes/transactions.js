const express = require('express');
const router = express.Router();
const db = require('../db');
const auth = require('../auth'); // Import auth

// GET all transactions
router.get('/', auth.authenticate, async (req, res) => {
    try {
        const { rows } = await db.query('SELECT * FROM transactions ORDER BY date DESC');
        res.json(rows);
    } catch (err) {
        console.error(err.message);
        res.status(500).send('Server error');
    }
});

// POST a new transaction
router.post('/', auth.authenticate, auth.authorize(['admin']), async (req, res) => {
    try {
        const { date, description, amount, type, category } = req.body;
        const { rows } = await db.query(
            'INSERT INTO transactions (date, description, amount, type, category) VALUES ($1, $2, $3, $4, $5) RETURNING *',
            [date, description, amount, type, category]
        );
        res.status(201).json(rows[0]);
    } catch (err) {
        console.error(err.message);
        res.status(500).send('Server error');
    }
});

// PUT (update) a transaction
router.put('/:id', auth.authenticate, auth.authorize(['admin']), async (req, res) => {
    try {
        const { id } = req.params;
        const { date, description, amount, type, category } = req.body;
        const { rows } = await db.query(
            'UPDATE transactions SET date = $1, description = $2, amount = $3, type = $4, category = $5 WHERE id = $6 RETURNING *',
            [date, description, amount, type, category, id]
        );
        if (rows.length === 0) {
            return res.status(404).json({ msg: 'Transaction not found' });
        }
        res.json(rows[0]);
    } catch (err) {
        console.error(err.message);
        res.status(500).send('Server error');
    }
});

// DELETE a transaction
router.delete('/:id', auth.authenticate, auth.authorize(['admin']), async (req, res) => {
    try {
        const { id } = req.params;
        const { rowCount } = await db.query('DELETE FROM transactions WHERE id = $1', [id]);
        if (rowCount === 0) {
            return res.status(404).json({ msg: 'Transaction not found' });
        }
        res.json({ msg: 'Transaction deleted' });
    } catch (err) {
        console.error(err.message);
        res.status(500).send('Server error');
    }
});

// GET financial report
router.get('/report', auth.authenticate, async (req, res) => {
    try {
        const { rows } = await db.query(`
            SELECT
                SUM(CASE WHEN type = 'income' THEN amount ELSE 0 END) as total_income,
                SUM(CASE WHEN type = 'expense' THEN amount ELSE 0 END) as total_expense,
                SUM(CASE WHEN type = 'income' THEN amount ELSE -amount END) as balance
            FROM transactions
        `);
        res.json(rows[0]);
    } catch (err) {
        console.error(err.message);
        res.status(500).send('Server error');
    }
});

module.exports = router;
