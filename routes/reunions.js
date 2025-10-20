const express = require('express');
const router = express.Router();
const db = require('../db');
const auth = require('../auth'); // Import auth

// GET all meetings
router.get('/', auth.authenticate, async (req, res) => {
    try {
        const { rows } = await db.query(`
            SELECT
                r.*,
                COALESCE(json_agg(json_build_object('id', m.id, 'full_name', m.full_name)) FILTER (WHERE m.id IS NOT NULL), '[]') AS members_present
            FROM
                reunions r
            LEFT JOIN
                reunion_members rm ON r.id = rm.reunion_id
            LEFT JOIN
                members m ON rm.member_id = m.id
            GROUP BY
                r.id
            ORDER BY
                r.date_reunion DESC
        `);
        res.json(rows);
    } catch (err) {
        console.error(err.message);
        res.status(500).send('Server error');
    }
});

// GET a single meeting by ID
router.get('/:id', auth.authenticate, async (req, res) => {
    try {
        const { id } = req.params;
        const { rows } = await db.query(`
            SELECT
                r.*,
                COALESCE(json_agg(json_build_object('id', m.id, 'full_name', m.full_name)) FILTER (WHERE m.id IS NOT NULL), '[]') AS members_present
            FROM
                reunions r
            LEFT JOIN
                reunion_members rm ON r.id = rm.reunion_id
            LEFT JOIN
                members m ON rm.member_id = m.id
            WHERE
                r.id = $1
            GROUP BY
                r.id
        `, [id]);

        if (rows.length === 0) {
            return res.status(404).json({ msg: 'Meeting not found' });
        }
        res.json(rows[0]);
    } catch (err) {
        console.error(err.message);
        res.status(500).send('Server error');
    }
});

// POST a new meeting
router.post('/', auth.authenticate, auth.authorize(['admin']), async (req, res) => {
    const client = await db.getClient();
    try {
        await client.query('BEGIN');
        const { titre, date_reunion, ordre_du_jour, decisions, actions_a_mener, statut, type_reunion, lieu, nombre_membres_presents, members_present_ids } = req.body;

        const { rows } = await client.query(
            'INSERT INTO reunions (titre, date_reunion, ordre_du_jour, decisions, actions_a_mener, statut, type_reunion, lieu, nombre_membres_presents) VALUES ($1, $2, $3, $4, $5, $6::statut_enum, $7::type_reunion_enum, $8, $9) RETURNING id',
            [titre, date_reunion, ordre_du_jour, decisions, actions_a_mener, statut, type_reunion, lieu, nombre_membres_presents]
        );
        const reunionId = rows[0].id;

        if (members_present_ids && members_present_ids.length > 0) {
            for (const memberId of members_present_ids) {
                await client.query('INSERT INTO reunion_members (reunion_id, member_id) VALUES ($1, $2)', [reunionId, memberId]);
            }
        }

        await client.query('COMMIT');
        res.status(201).json({ id: reunionId, msg: 'Reunion created successfully' });
    } catch (err) {
        await client.query('ROLLBACK');
        console.error(err.message);
        res.status(500).send('Server error');
    } finally {
        client.release();
    }
});

// PUT (update) a meeting
router.put('/:id', auth.authenticate, auth.authorize(['admin']), async (req, res) => {
    const client = await db.getClient();
    try {
        await client.query('BEGIN');
        const { id } = req.params;
        const { titre, date_reunion, ordre_du_jour, decisions, actions_a_mener, statut, type_reunion, lieu, nombre_membres_presents, members_present_ids } = req.body;

        const { rows } = await client.query(
            'UPDATE reunions SET titre = $1, date_reunion = $2, ordre_du_jour = $3, decisions = $4, actions_a_mener = $5, statut = $6::statut_enum, type_reunion = $7::type_reunion_enum, lieu = $8, nombre_membres_presents = $9, updated_at = CURRENT_TIMESTAMP WHERE id = $10 RETURNING *',
            [titre, date_reunion, ordre_du_jour, decisions, actions_a_mener, statut, type_reunion, lieu, nombre_membres_presents, id]
        );

        if (rows.length === 0) {
            await client.query('ROLLBACK');
            return res.status(404).json({ msg: 'Meeting not found' });
        }

        // Clear existing members for this reunion
        await client.query('DELETE FROM reunion_members WHERE reunion_id = $1', [id]);

        // Insert new members
        if (members_present_ids && members_present_ids.length > 0) {
            for (const memberId of members_present_ids) {
                await client.query('INSERT INTO reunion_members (reunion_id, member_id) VALUES ($1, $2)', [id, memberId]);
            }
        }

        await client.query('COMMIT');
        res.json(rows[0]);
    } catch (err) {
        await client.query('ROLLBACK');
        console.error(err.message);
        res.status(500).send('Server error');
    } finally {
        client.release();
    }
});

// DELETE a meeting
router.delete('/:id', auth.authenticate, auth.authorize(['admin']), async (req, res) => {
    try {
        const { id } = req.params;
        const { rowCount } = await db.query('DELETE FROM reunions WHERE id = $1', [id]);

        if (rowCount === 0) {
            return res.status(404).json({ msg: 'Meeting not found' });
        }
        res.json({ msg: 'Meeting deleted' });
    } catch (err) {
        console.error(err.message);
        res.status(500).send('Server error');
    }
});

module.exports = router;
