
const bcrypt = require('bcryptjs');
const fs = require('fs').promises;
const path = require('path');

const settingsFilePath = path.join(__dirname, 'config', 'settings.json');

require('dotenv').config();
const express = require('express');
const bodyParser = require('body-parser');
const db = require('./db');
const auth = require('./auth');
const rateLimit = require('express-rate-limit');
const PDFDocument = require('pdfkit');
const { Document, Packer, Paragraph, TextRun } = require('docx');
const { convert } = require('html-to-text');
const cors = require('cors');
const app = express();
app.set('trust proxy', 1); // ← Render utilise 1 proxy
//app.set('trust proxy', true);
app.use(cors({
    origin: ['http://localhost:3000', 'https://csmfr-fr.vercel.app'],
    methods: 'GET,HEAD,PUT,PATCH,POST,DELETE',
    credentials: true,
}));
const port = process.env.PORT || 5000;
app.listen(port, () => {
  console.log(`Server running on port ${port}`);
});
app.use(bodyParser.json());

app.use((req, res, next) => {
    console.log(`[${new Date().toISOString()}] ${req.method} ${req.url}`);
    next();
});

app.post('/api/register', auth.register);

const loginLimiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 10, // limit each IP to 10 requests per windowMs
    message: 'Too many login attempts from this IP, please try again after 15 minutes'
});
app.post('/api/login', loginLimiter, auth.login);


const profileRoutes = require('./routes/profile');
const reunionsRoutes = require('./routes/reunions');
const transactionsRoutes = require('./routes/transactions');
const adminRoutes = require('./routes/admin');

app.use('/api/profile', auth.authenticate, profileRoutes);
app.use('/api/reunions', auth.authenticate, reunionsRoutes);
app.use('/api/transactions', auth.authenticate, transactionsRoutes);
app.use('/api/admin', auth.authenticate, adminRoutes);

app.get('/', (req, res) => {
  res.send('CSMFR Backend is running!');
});

app.get('/', (req, res) => {
  res.send('CSMFR Backend is running!');
});

// ------------------ Admin Creation API (Temporary) ------------------
// This endpoint is for initial admin creation and should be removed or secured in production.
app.post('/api/admin/create', async (req, res) => {
    try {
        const { username, password } = req.body;

        // Check if an admin user already exists
        const existingAdmin = await db.query("SELECT * FROM users WHERE role = 'admin'");
        if (existingAdmin.rows.length > 0) {
            return res.status(403).json({ msg: 'Admin user already exists. Cannot create another via this endpoint.' });
        }

        const hashedPassword = await bcrypt.hash(password, 10);
        const newUser = await db.query(
            'INSERT INTO users (username, password, role) VALUES ($1, $2, $3) RETURNING *'
            , [username, hashedPassword, 'admin']
        );
        res.status(201).json({ msg: 'Admin user created successfully', user: newUser.rows[0] });
    } catch (err) {
        console.error(err.message);
        res.status(500).send('Server error');
    }
});

// ------------------ Security Groups API ------------------

// Get all security groups with their permissions
app.get('/api/admin/security-groups', auth.authenticate, auth.authorize(['admin']), async (req, res) => {
    try {
        const { rows: groups } = await db.query('SELECT * FROM security_groups ORDER BY name');
        
        for (const group of groups) {
            const { rows: permissions } = await db.query('SELECT module_name, can_read, can_write, can_edit, can_delete FROM group_permissions WHERE group_id = $1', [group.id]);
            group.permissions = permissions;
        }

        res.json(groups);
    } catch (err) {
        console.error(err.message);
        res.status(500).send('Server error');
    }
});

// Get a single security group with its permissions
app.get('/api/admin/security-groups/:id', auth.authenticate, auth.authorize(['admin']), async (req, res) => {
    try {
        const { id } = req.params;
        const { rows: groupRows } = await db.query('SELECT * FROM security_groups WHERE id = $1', [id]);
        if (groupRows.length === 0) {
            return res.status(404).json({ msg: 'Security group not found' });
        }
        const group = groupRows[0];

        const { rows: permissions } = await db.query('SELECT module_name, can_read, can_write, can_edit, can_delete FROM group_permissions WHERE group_id = $1', [group.id]);
        group.permissions = permissions;

        res.json(group);
    } catch (err) {
        console.error(err.message);
        res.status(500).send('Server error');
    }
});

// Create a new security group
app.post('/api/admin/security-groups', auth.authenticate, auth.authorize(['admin']), async (req, res) => {
    try {
        const { name, description, permissions } = req.body;

        const { rows: newGroupRows } = await db.query(
            'INSERT INTO security_groups (name, description) VALUES ($1, $2) RETURNING id'
            , [name, description]
        );
        const newGroupId = newGroupRows[0].id;

        for (const p of permissions) {
            await db.query(
                'INSERT INTO group_permissions (group_id, module_name, can_read, can_write, can_edit, can_delete) VALUES ($1, $2, $3, $4, $5, $6)'
                , [newGroupId, p.module_name, p.can_read, p.can_write, p.can_edit, p.can_delete]
            );
        }

        res.status(201).json({ msg: 'Security group created successfully', id: newGroupId });
    } catch (err) {
        console.error(err.message);
        res.status(500).send('Server error');
    }
});

// Update a security group
app.put('/api/admin/security-groups/:id', auth.authenticate, auth.authorize(['admin']), async (req, res) => {
    try {
        const { id } = req.params;
        const { name, description, permissions } = req.body;

        await db.query(
            'UPDATE security_groups SET name = $1, description = $2 WHERE id = $3'
            , [name, description, id]
        );

        // Delete existing permissions and insert new ones
        await db.query('DELETE FROM group_permissions WHERE group_id = $1', [id]);
        for (const p of permissions) {
            await db.query(
                'INSERT INTO group_permissions (group_id, module_name, can_read, can_write, can_edit, can_delete) VALUES ($1, $2, $3, $4, $5, $6)'
                , [id, p.module_name, p.can_read, p.can_write, p.can_edit, p.can_delete]
            );
        }

        res.json({ msg: 'Security group updated successfully' });
    } catch (err) {
        console.error(err.message);
        res.status(500).send('Server error');
    }
});

// Delete a security group
app.delete('/api/admin/security-groups/:id', auth.authenticate, auth.authorize(['admin']), async (req, res) => {
    try {
        const { id } = req.params;
        await db.query('DELETE FROM security_groups WHERE id = $1', [id]);
        res.json({ msg: 'Security group deleted successfully' });
    } catch (err) {
        console.error(err.message);
        res.status(500).send('Server error');
    }
});

// Update user's group
app.put('/api/admin/users/:id/group', auth.authenticate, auth.authorize(['admin']), async (req, res) => {
    try {
        const { id } = req.params;
        const { group_id } = req.body;

        await db.query(
            'UPDATE users SET group_id = $1 WHERE id = $2'
            , [group_id, id]
        );
        res.json({ msg: 'User group updated successfully' });
    } catch (err) {
        console.error(err.message);
        res.status(500).send('Server error');
    }
});

// ------------------ Members API ------------------

// Get all members
app.get('/api/members', auth.authenticate, async (req, res) => {
  try {
    const { search } = req.query;
    let query = 'SELECT * FROM members';
    const params = [];

    if (search) {
      query += ' WHERE full_name ILIKE $1';
      params.push(`%${search}%`);
    }

    query += ' ORDER BY id ASC';

    const { rows } = await db.query(query, params);
    res.json(rows);
  } catch (err) {
    console.error(err.message);
    res.status(500).send('Server error');
  }
});

// Get a single member
app.get('/api/members/:id', auth.authenticate, async (req, res) => {
  try {
    const { id } = req.params;
    const { rows } = await db.query('SELECT * FROM members WHERE id = $1', [id]);
    if (rows.length === 0) {
      return res.status(404).json({ msg: 'Member not found' });
    }
    res.json(rows[0]);
  } catch (err) {
    console.error(err.message);
    res.status(500).send('Server error');
  }
});

// Create a member
app.post('/api/members', auth.authenticate, auth.authorize(['admin']), async (req, res) => {
  try {
    const { full_name, contact_number, email, address, membership_start_date, status } = req.body;
    const newMember = await db.query(
      'INSERT INTO members (full_name, contact_number, email, address, membership_start_date, status) VALUES ($1, $2, $3, $4, $5, $6) RETURNING *',
      [full_name, contact_number, email, address, membership_start_date, status]
    );
    res.json(newMember.rows[0]);
  } catch (err) {
    console.error(err.message);
    res.status(500).send('Server error');
  }
});

// Update a member
app.put('/api/members/:id', auth.authenticate, auth.authorize(['admin']), async (req, res) => {
  try {
    const { id } = req.params;
    const { full_name, contact_number, email, address, membership_start_date, membership_end_date, status } = req.body;
    const updatedMember = await db.query(
      'UPDATE members SET full_name = $1, contact_number = $2, email = $3, address = $4, membership_start_date = $5, membership_end_date = $6, status = $7 WHERE id = $8 RETURNING *',
      [full_name, contact_number, email, address, membership_start_date, membership_end_date, status, id]
    );
    if (updatedMember.rows.length === 0) {
      return res.status(404).json({ msg: 'Member not found' });
    }
    res.json(updatedMember.rows[0]);
  } catch (err) {
    console.error(err.message);
    res.status(500).send('Server error');
  }
});

// Delete a member
app.delete('/api/members/:id', auth.authenticate, auth.authorize(['admin']), async (req, res) => {
  try {
    const { id } = req.params;
    const deleteOp = await db.query('DELETE FROM members WHERE id = $1 RETURNING *', [id]);
    if (deleteOp.rowCount === 0) {
      return res.status(404).json({ msg: 'Member not found' });
    }
    res.json({ msg: 'Member deleted' });
  } catch (err) {
    console.error(err.message);
    res.status(500).send('Server error');
  }
});

// Get missing contributions for a member
app.get('/api/members/:id/missing-contributions', auth.authenticate, async (req, res) => {
  try {
    const { id } = req.params;

    // Read settings
    const settingsData = await fs.readFile(settingsFilePath, 'utf8');
    const settings = JSON.parse(settingsData);
    const expectedAnnualContribution = settings.contributions.standardAnnualAmount; // 240; // euros per year

    // Fetch member's start date
    const memberResult = await db.query('SELECT membership_start_date FROM members WHERE id = $1', [id]);
    if (memberResult.rows.length === 0) {
      return res.status(404).json({ msg: 'Member not found' });
    }
    const membershipStartDate = new Date(memberResult.rows[0].membership_start_date);

    // Calculate expected contributions
    const now = new Date();
    const yearsDiff = now.getFullYear() - membershipStartDate.getFullYear();
    const monthsDiff = now.getMonth() - membershipStartDate.getMonth();
    let totalMonths = yearsDiff * 12 + monthsDiff;

    // Adjust if current day is before start day in the current month
    if (now.getDate() < membershipStartDate.getDate()) {
      totalMonths--;
    }

    // Ensure at least 0 months if start date is in the future or current month is not yet passed
    if (totalMonths < 0) {
        totalMonths = 0;
    }

    const expectedMonthlyContribution = expectedAnnualContribution / 12;
    const totalExpected = totalMonths * expectedMonthlyContribution;

    // Fetch all contributions for the member
    const contributionsResult = await db.query('SELECT amount, contribution_year, contribution_month FROM contributions WHERE member_id = $1', [id]);
    const contributions = contributionsResult.rows;

    // Calculate total paid
    const totalPaid = contributions.reduce((sum, c) => sum + parseFloat(c.amount), 0);

    const missingContributions = totalExpected - totalPaid;

    // Get missing months
    const paidMonths = new Set(contributions.map(c => `${c.contribution_year}-${c.contribution_month}`));
    const missingMonths = [];
    let currentDate = new Date(membershipStartDate);
    while (currentDate <= now) {
        const year = currentDate.getFullYear();
        const month = currentDate.getMonth() + 1;
        if (!paidMonths.has(`${year}-${month}`)) {
            missingMonths.push({ year, month });
        }
        currentDate.setMonth(currentDate.getMonth() + 1);
    }

    res.json({
      expected: parseFloat(totalExpected.toFixed(2)),
      paid: parseFloat(totalPaid.toFixed(2)),
      missing: parseFloat(missingContributions.toFixed(2)),
      missingMonths: missingMonths
    });

  } catch (err) {
    console.error(err.message);
    res.status(500).send('Server error');
  }
});

// Export reunion details to PDF or DOCX
app.get('/api/reunions/:id/export', auth.authenticate, async (req, res) => {
    try {
        const { id } = req.params;
        const { format } = req.query;

        const reunionResult = await db.query('SELECT * FROM reunions WHERE id = $1', [id]);
        const reunion = reunionResult.rows[0];

        if (!reunion) {
            return res.status(404).json({ msg: 'Reunion not found' });
        }

        // Fetch members present for the reunion
        const membersPresentResult = await db.query(`
            SELECT m.full_name
            FROM members m
            JOIN reunion_members rm ON m.id = rm.member_id
            WHERE rm.reunion_id = $1
        `, [id]);
        reunion.members_present = membersPresentResult.rows.map(row => row.full_name);

        const reunionDate = new Date(reunion.date_reunion).toLocaleString('fr-FR');
        const membersList = reunion.members_present.length > 0 ? reunion.members_present.join(', ') : 'Non spécifié';

        // Convert HTML content to plain text
        const ordreDuJourText = reunion.ordre_du_jour ? convert(reunion.ordre_du_jour, { wordwrap: 130 }) : 'Non spécifié';
        const decisionsText = reunion.decisions ? convert(reunion.decisions, { wordwrap: 130 }) : 'Non spécifié';
        const actionsAMenerText = reunion.actions_a_mener ? convert(reunion.actions_a_mener, { wordwrap: 130 }) : 'Non spécifié';

        if (format === 'pdf') {
            const doc = new PDFDocument();
            const filename = `compte-rendu-${reunion.titre.replace(/\s+/g, '_')}.pdf`;

            res.setHeader('Content-Disposition', `attachment; filename="${filename}"`);
            res.setHeader('Content-Type', 'application/pdf');

            doc.pipe(res);

            doc.fontSize(20).text('Compte Rendu de Réunion', { align: 'center' });
            doc.moveDown();
            doc.fontSize(14).text(`Titre: ${reunion.titre}`);
            doc.text(`Date: ${reunionDate}`);
            doc.text(`Statut: ${reunion.statut}`);
            doc.text(`Type: ${reunion.type_reunion}`);
            doc.text(`Lieu: ${reunion.lieu || 'Non spécifié'}`);
            doc.text(`Membres présents: ${membersList}`);
            doc.moveDown();

            doc.fontSize(16).text('Ordre du Jour:');
            doc.fontSize(12).text(ordreDuJourText);
            doc.moveDown();

            doc.fontSize(16).text('Décisions Prises:');
            doc.fontSize(12).text(decisionsText);
            doc.moveDown();

            doc.fontSize(16).text('Actions à Mener:');
            doc.fontSize(12).text(actionsAMenerText);

            doc.end();

        } else if (format === 'docx') {
            const doc = new Document({
                sections: [{
                    properties: {},
                    children: [
                        new Paragraph({
                            children: [
                                new TextRun({ text: 'Compte Rendu de Réunion', bold: true, size: 40 }),
                            ],
                            alignment: 'center',
                        }),
                        new Paragraph({ text: '' }),
                        new Paragraph({ children: [new TextRun({ text: `Titre: ${reunion.titre}`, bold: true })] }),
                        new Paragraph({ children: [new TextRun({ text: `Date: ${reunionDate}`, bold: true })] }),
                        new Paragraph({ children: [new TextRun({ text: `Statut: ${reunion.statut}`, bold: true })] }),
                        new Paragraph({ children: [new TextRun({ text: `Type: ${reunion.type_reunion}`, bold: true })] }),
                        new Paragraph({ children: [new TextRun({ text: `Lieu: ${reunion.lieu || 'Non spécifié'}`, bold: true })] }),
                        new Paragraph({ children: [new TextRun({ text: `Membres présents: ${membersList}`, bold: true })] }),
                        new Paragraph({ text: '' }),
                        new Paragraph({ children: [new TextRun({ text: 'Ordre du Jour:', bold: true })] }),
                        new Paragraph({ text: ordreDuJourText }),
                        new Paragraph({ text: '' }),
                        new Paragraph({ children: [new TextRun({ text: 'Décisions Prises:', bold: true })] }),
                        new Paragraph({ text: decisionsText }),
                        new Paragraph({ text: '' }),
                        new Paragraph({ children: [new TextRun({ text: 'Actions à Mener:', bold: true })] }),
                        new Paragraph({ text: actionsAMenerText }),
                    ],
                }],
            });

            const buffer = await Packer.toBuffer(doc);
            const filename = `compte-rendu-${reunion.titre.replace(/\s+/g, '_')}.docx`;

            res.setHeader('Content-Disposition', `attachment; filename="${filename}"`);
            res.setHeader('Content-Type', 'application/vnd.openxmlformats-officedocument.wordprocessingml.document');
            res.send(buffer);

        } else {
            res.status(400).json({ msg: 'Invalid format specified. Use "pdf" or "docx".' });
        }

    } catch (err) {
        console.error(err.message);
        res.status(500).send('Server error');
    }
});

// ------------------ Contributions API ------------------

// Get all contributions
app.get('/api/contributions', auth.authenticate, async (req, res) => {
    try {
        const { month, year, page = 1, limit = 25 } = req.query;
        const offset = (page - 1) * limit;

        let whereClause = '';
        const params = [];
        let paramIndex = 1;

        if (month && year) {
            whereClause = ` WHERE c.contribution_month = $${paramIndex++} AND c.contribution_year = $${paramIndex++}`;
            params.push(month, year);
        } else if (year) {
            whereClause = ` WHERE c.contribution_year = $${paramIndex++}`;
            params.push(year);
        }

        const countQuery = `SELECT COUNT(*) FROM contributions c${whereClause}`;
        const { rows: countRows } = await db.query(countQuery, params);
        const totalContributions = parseInt(countRows[0].count, 10);

        const query = `
            SELECT c.*, m.full_name 
            FROM contributions c 
            JOIN members m ON c.member_id = m.id
            ${whereClause} 
            ORDER BY c.contribution_date DESC
            LIMIT $${paramIndex++} OFFSET $${paramIndex++}
        `;
        params.push(limit, offset);

        const { rows } = await db.query(query, params);
        res.json({
            contributions: rows,
            totalPages: Math.ceil(totalContributions / limit),
            currentPage: parseInt(page, 10),
        });
    } catch (err) {
        console.error(err.message);
        res.status(500).send('Server error');
    }
});

// Get a single contribution
app.get('/api/contributions/:id', auth.authenticate, async (req, res) => {
    try {
        const { id } = req.params;
        const { rows } = await db.query('SELECT * FROM contributions WHERE id = $1', [id]);
        if (rows.length === 0) {
            return res.status(404).json({ msg: 'Contribution not found' });
        }
        res.json(rows[0]);
    } catch (err) {
        console.error(err.message);
        res.status(500).send('Server error');
    }
});

// Get all contributions for a specific member
app.get('/api/contributions/member/:memberId', auth.authenticate, async (req, res) => {
    try {
        const { memberId } = req.params;
        const { month, year } = req.query;

        let query = 'SELECT * FROM contributions WHERE member_id = $1';
        const params = [memberId];

        if (month && year) {
            query += ' AND contribution_month = $2 AND contribution_year = $3';
            params.push(month, year);
        } else if (year) {
            query += ' AND contribution_year = $2';
            params.push(year);
        }

        query += ' ORDER BY contribution_date DESC';

        const { rows } = await db.query(query, params);
        res.json(rows);
    } catch (err) {
        console.error(err.message);
        res.status(500).send('Server error');
    }
});

// Export all contributions to CSV
app.get('/api/contributions/export', auth.authenticate, auth.authorize(['admin']), async (req, res) => {
    try {
        const { rows } = await db.query(`
            SELECT
                c.contribution_year,
                c.contribution_month,
                c.contribution_date,
                c.amount,
                m.full_name as member_name,
                c.payment_method
            FROM
                contributions c
            JOIN
                members m ON c.member_id = m.id
            ORDER BY
                c.contribution_year DESC, c.contribution_month DESC, c.contribution_date DESC
        `);

        if (rows.length === 0) {
            return res.status(404).send('No contributions found to export.');
        }

        // CSV Header
        const csvHeader = 'Year,Month,Date,Amount,Member Name,Payment Method\n';

        // CSV Rows
        const csvRows = rows.map(row => {
            const date = new Date(row.contribution_date).toLocaleDateString('en-CA'); // YYYY-MM-DD
            return `${row.contribution_year},${row.contribution_month},${date},${row.amount},"${row.member_name}",${row.payment_method}`;
        }).join('\n');

        const csv = csvHeader + csvRows;

        res.header('Content-Type', 'text/csv');
        res.attachment('contributions_export.csv');
        res.send(csv);

    } catch (err) {
        console.error('Error exporting contributions:', err.message);
        res.status(500).send('Server error');
    }
});

// Add a new contribution
app.post('/api/contributions', auth.authenticate, auth.authorize(['admin']), async (req, res) => {
    try {
        const { member_id, amount, contribution_date, contribution_month, contribution_year, payment_method } = req.body;
        const newContribution = await db.query(
            'INSERT INTO contributions (member_id, amount, contribution_date, contribution_month, contribution_year, payment_method) VALUES ($1, $2, $3, $4, $5, $6) RETURNING *',
            [member_id, amount, contribution_date, contribution_month, contribution_year, payment_method]
        );
        res.json(newContribution.rows[0]);
    } catch (err) {
        console.error(err.message);
        res.status(500).send('Server error');
    }
});

// Update a contribution
app.put('/api/contributions/:id', auth.authenticate, auth.authorize(['admin']), async (req, res) => {
    try {
        const { id } = req.params;
        const { amount, contribution_date, contribution_month, contribution_year, payment_method } = req.body;
        const updatedContribution = await db.query(
            'UPDATE contributions SET amount = $1, contribution_date = $2, contribution_month = $3, contribution_year = $4, payment_method = $5 WHERE id = $6 RETURNING *',
            [amount, contribution_date, contribution_month, contribution_year, payment_method, id]
        );
        if (updatedContribution.rows.length === 0) {
            return res.status(404).json({ msg: 'Contribution not found' });
        }
        res.json(updatedContribution.rows[0]);
    } catch (err) {
        console.error(err.message);
        res.status(500).send('Server error');
    }
});

// Delete a contribution
app.delete('/api/contributions/:id', auth.authenticate, auth.authorize(['admin']), async (req, res) => {
    try {
        const { id } = req.params;
        const deleteOp = await db.query('DELETE FROM contributions WHERE id = $1 RETURNING *', [id]);
        if (deleteOp.rowCount === 0) {
            return res.status(404).json({ msg: 'Contribution not found' });
        }
        res.json({ msg: 'Contribution deleted' });
    } catch (err) {
        console.error(err.message);
        res.status(500).send('Server error');
    }
});

// ------------------ Reporting API ------------------

// Get contribution summary
app.get('/api/reports/contribution-summary', auth.authenticate, async (req, res) => {
    try {
        const { rows } = await db.query(`
            SELECT 
                m.full_name, 
                SUM(c.amount) as total_amount,
                COUNT(c.id) as total_contributions
            FROM 
                members m
            JOIN 
                contributions c ON m.id = c.member_id
            GROUP BY 
                m.full_name
            ORDER BY 
                total_amount DESC
        `);
        res.json(rows);
    } catch (err) {
        console.error(err.message);
        res.status(500).send('Server error');
    }
});

// Get all contributions for a specific member for a specific year
app.get('/api/reports/member-contributions/:memberId/:year', auth.authenticate, async (req, res) => {
    try {
        const { memberId, year } = req.params;
        const { rows } = await db.query(
            'SELECT * FROM contributions WHERE member_id = $1 AND contribution_year = $2 ORDER BY contribution_date DESC',
            [memberId, year]
        );
        res.json(rows);
    } catch (err) {
        console.error(err.message);
        res.status(500).send('Server error');
    }
});

// Get detailed contributions report by member and year
app.get('/api/reports/member-contributions-by-year', auth.authenticate, async (req, res) => {
    try {
        const { page = 1, limit = 10, memberId } = req.query;
        const offset = (page - 1) * limit;

        if (memberId) {
            const membersResult = await db.query('SELECT id, full_name, membership_start_date FROM members WHERE id = $1', [memberId]);
            const member = membersResult.rows[0];

            if (!member) {
                return res.status(404).json({ msg: 'Member not found' });
            }

            const contributionsResult = await db.query('SELECT id, member_id, amount, contribution_date, contribution_month, contribution_year FROM contributions WHERE member_id = $1 ORDER BY contribution_year DESC, contribution_month DESC', [memberId]);
            const contributions = contributionsResult.rows;

            const contributions_by_year = contributions.reduce((acc, contribution) => {
                const year = contribution.contribution_year;
                if (!acc[year]) {
                    acc[year] = [];
                }
                acc[year].push(contribution);
                return acc;
            }, {});

            const reportData = {
                id: member.id,
                full_name: member.full_name,
                membership_start_date: member.membership_start_date,
                contributions_by_year: contributions_by_year
            };

            return res.json(reportData);
        }

        // 1. Get a page of members
        const membersResult = await db.query('SELECT id, full_name, membership_start_date FROM members ORDER BY full_name LIMIT $1 OFFSET $2', [limit, offset]);
        const members = membersResult.rows;
        const memberIds = members.map(m => m.id);

        if (memberIds.length === 0) {
            return res.json({
                reportData: [],
                totalPages: 0,
                currentPage: parseInt(page, 10),
            });
        }

        // 2. Get all contributions for those members
        const contributionsResult = await db.query('SELECT id, member_id, amount, contribution_date, contribution_month, contribution_year FROM contributions WHERE member_id = ANY($1) ORDER BY contribution_year DESC, contribution_month DESC', [memberIds]);
        const contributions = contributionsResult.rows;

        // 3. Group contributions by member
        const contributionsByMember = contributions.reduce((acc, contribution) => {
            if (!acc[contribution.member_id]) {
                acc[contribution.member_id] = [];
            }
            acc[contribution.member_id].push(contribution);
            return acc;
        }, {});

        // 4. Build the final report data
        const reportData = members.map(member => {
            const memberContributions = contributionsByMember[member.id] || [];
            const contributions_by_year = memberContributions.reduce((acc, contribution) => {
                const year = contribution.contribution_year;
                if (!acc[year]) {
                    acc[year] = [];
                }
                acc[year].push(contribution);
                return acc;
            }, {});

            return {
                id: member.id,
                full_name: member.full_name,
                membership_start_date: member.membership_start_date,
                contributions_by_year: contributions_by_year
            };
        });

        const totalMembersResult = await db.query('SELECT COUNT(*) FROM members');
        const totalMembers = parseInt(totalMembersResult.rows[0].count, 10);

        res.json({
            reportData,
            totalPages: Math.ceil(totalMembers / limit),
            currentPage: parseInt(page, 10),
        });
    } catch (err) {
        console.error(err.message);
        res.status(500).send('Server error');
    }
});

// ------------------ Dashboard API ------------------

app.get('/api/dashboard', auth.authenticate, async (req, res) => {
    try {
        const totalContributionsQuery = await db.query(
            `SELECT SUM(amount) as total_amount
             FROM contributions
             WHERE contribution_month = EXTRACT(MONTH FROM CURRENT_DATE)
               AND contribution_year = EXTRACT(YEAR FROM CURRENT_DATE)`
        );

const activeMembersQuery = await db.query("SELECT COUNT(*) FROM members WHERE LOWER(status) = 'active'");

        const overduePaymentsQuery = await db.query("SELECT COUNT(*) FROM members WHERE LOWER(status) = 'overdue'");

        const newMembersQuery = await db.query(
            `SELECT COUNT(*)
             FROM members
             WHERE membership_start_date >= DATE_TRUNC('month', CURRENT_DATE)`
        );

        const recentMembersQuery = await db.query('SELECT * FROM members ORDER BY membership_start_date DESC LIMIT 5');

        const recentContributionsQuery = await db.query(`
            SELECT c.*, m.full_name as member_name
            FROM contributions c
            JOIN members m ON c.member_id = m.id
            ORDER BY c.contribution_date DESC
            LIMIT 5
        `);

        res.json({
            stats: {
                totalContributions: totalContributionsQuery.rows[0].total_amount || 0,
                activeMembers: activeMembersQuery.rows[0].count || 0,
                overduePayments: overduePaymentsQuery.rows[0].count || 0,
                newMembers: newMembersQuery.rows[0].count || 0,
            },
            recentMembers: recentMembersQuery.rows,
            recentContributions: recentContributionsQuery.rows,
        });
    } catch (err) {
        console.error(err.message);
        res.status(500).send('Server error');
    }
});

// Get dashboard stats
app.get('/api/dashboard/stats', auth.authenticate, async (req, res) => {
    try {
        const totalContributionsQuery = await db.query(
            `SELECT SUM(amount) as total_amount
             FROM contributions
             WHERE contribution_month = EXTRACT(MONTH FROM CURRENT_DATE)
               AND contribution_year = EXTRACT(YEAR FROM CURRENT_DATE)`
        );

        const activeMembersQuery = await db.query("SELECT COUNT(*) FROM members WHERE status = 'Active'");

        // This is a simplified overdue logic. A more robust solution would be needed for a real application.
        const overduePaymentsQuery = await db.query("SELECT COUNT(*) FROM members WHERE status = 'Overdue'");

        const newMembersQuery = await db.query(
            `SELECT COUNT(*)
             FROM members
             WHERE membership_start_date >= DATE_TRUNC('month', CURRENT_DATE)`
        );

        res.json({
            totalContributions: totalContributionsQuery.rows[0].total_amount || 0,
            activeMembers: activeMembersQuery.rows[0].count || 0,
            overduePayments: overduePaymentsQuery.rows[0].count || 0,
            newMembers: newMembersQuery.rows[0].count || 0,
        });
    } catch (err) {
        console.error(err.message);
        res.status(500).send('Server error');
    }
});

// Get recent members
app.get('/api/dashboard/recent-members', auth.authenticate, async (req, res) => {
    try {
        const { rows } = await db.query('SELECT * FROM members ORDER BY membership_start_date DESC LIMIT 5');
        res.json(rows);
    } catch (err) {
        console.error(err.message);
        res.status(500).send('Server error');
    }
});

// Get recent contributions
app.get('/api/dashboard/recent-contributions', auth.authenticate, async (req, res) => {
    try {
        const { rows } = await db.query(`
            SELECT c.*, m.full_name as member_name
            FROM contributions c
            JOIN members m ON c.member_id = m.id
            ORDER BY c.contribution_date DESC
            LIMIT 5
        `);
        res.json(rows);
    } catch (err) {
        console.error(err.message);
        res.status(500).send('Server error');
    }
});

// Get contribution trends
app.get('/api/dashboard/contribution-trends', auth.authenticate, async (req, res) => {
    try {
        const { range } = req.query;
        let whereClause = '';
        let select = '';
        let groupBy = '';
        let orderBy = '';

        switch (range) {
            case 'Année en cours':
                select = "TO_CHAR(contribution_date, 'YYYY-MM') as month";
                whereClause = `WHERE contribution_year = EXTRACT(YEAR FROM CURRENT_DATE)`
                groupBy = 'month';
                orderBy = 'month';
                break;
            case 'Trimestre actuel':
                select = "TO_CHAR(contribution_date, 'YYYY-MM') as month";
                whereClause = `WHERE contribution_date >= DATE_TRUNC('quarter', CURRENT_DATE)`
                groupBy = 'month';
                orderBy = 'month';
                break;
            case 'Par année':
                select = 'contribution_year as year';
                whereClause = '';
                groupBy = 'year';
                orderBy = 'year';
                break;
            case '6 derniers mois':
            default:
                select = "TO_CHAR(contribution_date, 'YYYY-MM') as month";
                whereClause = `WHERE contribution_date >= DATE_TRUNC('month', CURRENT_DATE) - INTERVAL '5 months'`;
                groupBy = 'month';
                orderBy = 'month';
                break;
        }

        const { rows } = await db.query(`
            SELECT
                ${select},
                SUM(amount) as "totalAmount"
            FROM
                contributions
            ${whereClause}
            GROUP BY
                ${groupBy}
            ORDER BY
                ${orderBy};
        `);

        if (range === 'Par année') {
            const labels = rows.map(row => ({
                label: row.year.toString(),
                data: parseFloat(row.totalAmount)
            }));
            return res.json(labels);
        }

        const monthNames = ["Jan", "Fév", "Mar", "Avr", "Mai", "Juin", "Juil", "Aoû", "Sep", "Oct", "Nov", "Déc"];
        const trendsMap = new Map(rows.map(row => [row.month, parseFloat(row.totalAmount)]));

        let labels = [];
        if (range === 'Année en cours') {
            labels = monthNames.map((name, index) => {
                const year = new Date().getFullYear();
                const monthKey = `${year}-${(index + 1).toString().padStart(2, '0')}`;
                return {
                    label: name,
                    data: trendsMap.get(monthKey) || 0
                }
            });
        } else if (range === 'Trimestre actuel') {
            const quarter = Math.floor(new Date().getMonth() / 3);
            const startMonth = quarter * 3;
            for (let i = 0; i < 3; i++) {
                const monthIndex = startMonth + i;
                const year = new Date().getFullYear();
                const monthKey = `${year}-${(monthIndex + 1).toString().padStart(2, '0')}`;
                labels.push({
                    label: monthNames[monthIndex],
                    data: trendsMap.get(monthKey) || 0
                });
            }
        } else { // 6 derniers mois
            for (let i = 5; i >= 0; i--) {
                const date = new Date();
                date.setMonth(date.getMonth() - i);
                const month = date.getMonth();
                const year = date.getFullYear();
                const monthKey = `${year}-${(month + 1).toString().padStart(2, '0')}`;
                labels.push({
                    label: monthNames[month],
                    data: trendsMap.get(monthKey) || 0
                });
            }
        }

        res.json(labels);
    } catch (err) {
        console.error(err.message);
        res.status(500).send('Server error');
    }
});

// Get members in arrears
app.get('/api/dashboard/members-in-arrears', auth.authenticate, async (req, res) => {
    try {
        const { years_in_arrears } = req.query;
        const arrearsThreshold = years_in_arrears ? parseInt(years_in_arrears, 10) * 12 : 24;

        const membersResult = await db.query('SELECT * FROM members');
        const members = membersResult.rows;

        const settingsData = await fs.readFile(settingsFilePath, 'utf8');
        const settings = JSON.parse(settingsData);
        const expectedMonthlyContribution = settings.contributions.standardMonthlyAmount;

        const membersInArrears = [];

        for (const member of members) {
            const contributionsResult = await db.query('SELECT amount, contribution_year, contribution_month FROM contributions WHERE member_id = $1', [member.id]);
            const contributions = contributionsResult.rows;

            const membershipStartDate = new Date(member.membership_start_date);
            const now = new Date();
            let totalMonths = (now.getFullYear() - membershipStartDate.getFullYear()) * 12 + (now.getMonth() - membershipStartDate.getMonth());
            if (now.getDate() < membershipStartDate.getDate()) {
                totalMonths--;
            }
            if (totalMonths < 0) {
                totalMonths = 0;
            }

            const paidMonths = new Set(contributions.map(c => `${c.contribution_year}-${c.contribution_month}`));
            let missingMonthsCount = 0;
            let currentDate = new Date(membershipStartDate);
            while (currentDate <= now) {
                const year = currentDate.getFullYear();
                const month = currentDate.getMonth() + 1;
                if (!paidMonths.has(`${year}-${month}`)) {
                    missingMonthsCount++;
                }
                currentDate.setMonth(currentDate.getMonth() + 1);
            }

            if (missingMonthsCount > arrearsThreshold) {
                membersInArrears.push({
                    id: member.id,
                    full_name: member.full_name,
                    years_in_arrears: Math.floor(missingMonthsCount / 12),
                    amount_due: missingMonthsCount * expectedMonthlyContribution,
                });
            }
        }

        res.json(membersInArrears);
    } catch (err) {
        console.error(err.message);
        res.status(500).send('Server error');
    }
});

// ------------------ Settings API ------------------

// Get application settings
app.get('/api/settings', auth.authenticate, async (req, res) => {
    try {
        const data = await fs.readFile(settingsFilePath, 'utf8');
        res.json(JSON.parse(data));
    } catch (err) {
        console.error('Error reading settings file:', err.message);
        res.status(500).send('Server error');
    }
});

// Update application settings
app.post('/api/settings', auth.authenticate, auth.authorize(['admin']), async (req, res) => {
    try {
        const newSettings = req.body;
        await fs.writeFile(settingsFilePath, JSON.stringify(newSettings, null, 2), 'utf8');
        res.json({ message: 'Settings updated successfully', settings: newSettings });
    } catch (err) {
        console.error('Error writing settings file:', err.message);
        res.status(500).send('Server error');
    }
});

app.listen(port, () => {
  console.log(`Server running on port ${port}`);
});
