const db = require('./db');

const fixConstraint = async () => {
    const dropConstraintQuery = 'ALTER TABLE reunions DROP CONSTRAINT IF EXISTS reunions_statut_check;';
    const addConstraintQuery = `ALTER TABLE reunions ADD CONSTRAINT reunions_statut_check CHECK (statut IN ('planifiée', 'en_cours', 'terminée', 'annulée'));`;

    try {
        console.log('Dropping existing constraint (if it exists)...');
        await db.query(dropConstraintQuery);
        console.log('Constraint dropped.');

        console.log('Adding correct constraint...');
        await db.query(addConstraintQuery);
        console.log('Constraint added successfully.');

        console.log('Database schema has been corrected.');

    } catch (err) {
        console.error('Fatal error during constraint fix:', err);
        process.exit(1);
    }
};

fixConstraint();
