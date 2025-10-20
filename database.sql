CREATE TABLE members (
    id SERIAL PRIMARY KEY,
    full_name VARCHAR(255) NOT NULL,
    contact_number VARCHAR(50),
    email VARCHAR(255) UNIQUE,
    address TEXT,
    membership_start_date DATE,
    membership_end_date DATE,
    status VARCHAR(50)
);

CREATE TABLE contributions (
    id SERIAL PRIMARY KEY,
    member_id INTEGER REFERENCES members(id) ON DELETE CASCADE,
    amount NUMERIC(10, 2) NOT NULL,
    contribution_date DATE NOT NULL,
    contribution_month INTEGER NOT NULL,
    contribution_year INTEGER NOT NULL,
    payment_method VARCHAR(100)
);

-- Security Groups Table
CREATE TABLE security_groups (
    id SERIAL PRIMARY KEY,
    name VARCHAR(255) NOT NULL UNIQUE,
    description TEXT
);

-- Group Permissions Table
CREATE TABLE group_permissions (
    group_id INTEGER REFERENCES security_groups(id) ON DELETE CASCADE,
    module_name VARCHAR(50) NOT NULL, -- e.g., 'members', 'contributions', 'finances', 'reports', 'reunions'
    can_read BOOLEAN DEFAULT FALSE,
    can_write BOOLEAN DEFAULT FALSE,
    can_edit BOOLEAN DEFAULT FALSE,
    can_delete BOOLEAN DEFAULT FALSE,
    PRIMARY KEY (group_id, module_name)
);

CREATE TABLE users (
    id SERIAL PRIMARY KEY,
    username VARCHAR(255) NOT NULL UNIQUE,
    password VARCHAR(255) NOT NULL,
    role VARCHAR(50) NOT NULL DEFAULT 'user',
    full_name VARCHAR(255),
    phone_number VARCHAR(50),
    profile_picture_url TEXT,
    two_factor_auth_enabled BOOLEAN DEFAULT FALSE,
    interface_language VARCHAR(50) DEFAULT 'Français',
    date_format VARCHAR(50) DEFAULT 'DD/MM/YYYY',
    number_format VARCHAR(50) DEFAULT '1 000',
    email_notifications JSONB DEFAULT '{}',
    last_login TIMESTAMP,
    status VARCHAR(50) NOT NULL DEFAULT 'active',
    group_id INTEGER REFERENCES security_groups(id) ON DELETE SET NULL
);

CREATE TYPE statut_enum AS ENUM ('planifiee', 'en_cours', 'terminee', 'annulee');
CREATE TYPE type_reunion_enum AS ENUM ('presentiel', 'distanciel', 'hybride');

CREATE TABLE reunions (
    id SERIAL PRIMARY KEY,
    titre VARCHAR(255) NOT NULL,
    date_reunion TIMESTAMP NOT NULL,
    lieu VARCHAR(255),
    ordre_du_jour TEXT,
    decisions TEXT,
    actions_a_mener TEXT,
    statut statut_enum NOT NULL,
    type_reunion type_reunion_enum,
    nombre_membres_presents INTEGER DEFAULT 0,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP
);

CREATE TABLE reunion_members (
    reunion_id INTEGER REFERENCES reunions(id) ON DELETE CASCADE,
    member_id INTEGER REFERENCES members(id) ON DELETE CASCADE,
    PRIMARY KEY (reunion_id, member_id)
);

CREATE TABLE transactions (
    id SERIAL PRIMARY KEY,
    date DATE NOT NULL,
    description TEXT NOT NULL,
    amount NUMERIC(10, 2) NOT NULL,
    type VARCHAR(50) NOT NULL, -- 'income' or 'expense'
    category VARCHAR(100),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);