const db = require('./db');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');

const saltRounds = 10;

const register = async (req, res) => {
    const { username, password, full_name, phone_number, profile_picture_url, two_factor_auth_enabled, interface_language, date_format, number_format, email_notifications } = req.body;
    const role = req.body.role || 'user';

    try {
        const hashedPassword = await bcrypt.hash(password, saltRounds);
        const result = await db.query(
            'INSERT INTO users (username, password, role, full_name, phone_number, profile_picture_url, two_factor_auth_enabled, interface_language, date_format, number_format, email_notifications) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11) RETURNING *',
            [username, hashedPassword, role, full_name, phone_number, profile_picture_url, two_factor_auth_enabled, interface_language, date_format, number_format, email_notifications]
        );
        const user = result.rows[0];
        const token = jwt.sign({ id: user.id, username: user.username, role: user.role }, 'secret', { expiresIn: '1h' });
        res.status(201).json({ token });
    } catch (error) {
        console.error("Registration error:", error);
        res.status(500).json({ error: error.message });
    }
};

const login = async (req, res) => {
    const { username, password } = req.body;

    try {
        const result = await db.query('SELECT * FROM users WHERE username = $1', [username]);
        if (result.rows.length > 0) {
            const user = result.rows[0];

            if (user.status === 'inactive') {
                return res.status(403).json({ error: 'Votre compte est inactif. Contactez l’administrateur.' });
            }

            const match = await bcrypt.compare(password, user.password);
            if (match) {
                const token = jwt.sign({ id: user.id, username: user.username, role: user.role }, 'secret', { expiresIn: '1h' });
                res.status(200).json({ token });
            } else {
                res.status(401).json({ error: 'Invalid credentials' });
            }
        } else {
            res.status(404).json({ error: 'User not found' });
        }
    } catch (error) {
        console.error("Login error:", error);
        res.status(500).json({ error: error.message });
    }
};

const authenticate = (req, res, next) => {
    const token = req.headers.authorization?.split(' ')[1];
    if (!token) {
        return res.status(401).json({ error: 'Access denied. No token provided.' });
    }

    try {
        const decoded = jwt.verify(token, 'secret');
        req.user = decoded;
        next();
    } catch (error) {
        res.status(400).json({ error: 'Invalid token.' });
    }
};

const authorize = (roles = []) => {
    if (typeof roles === 'string') {
        roles = [roles];
    }

    return (req, res, next) => {
        console.log('Authorize middleware: req.user:', req.user);
        console.log('Authorize middleware: Allowed roles:', roles);

        if (!req.user || !req.user.role) {
            console.log('Authorize middleware: User not authenticated or role missing.');
            return res.status(401).json({ error: 'Unauthorized: User role not found.' });
        }

        if (roles.length && !roles.includes(req.user.role)) {
            console.log(`Authorize middleware: User role '${req.user.role}' not in allowed roles: ${roles.join(', ')}.`);
            return res.status(403).json({ error: 'Forbidden: You do not have permission to access this resource.' });
        }

        console.log('Authorize middleware: User authorized.');
        next();
    };
};

module.exports = {
    register,
    login,
    authenticate,
    authorize,
};
