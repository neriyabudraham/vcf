CREATE TABLE IF NOT EXISTS uploaded_files (
    id SERIAL PRIMARY KEY,
    original_name VARCHAR(255),
    file_path VARCHAR(255),
    headers JSONB, -- שומר את רשימת העמודות שזוהו
    status VARCHAR(50) DEFAULT 'pending', -- pending, processed
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS contact_groups (
    id SERIAL PRIMARY KEY,
    name VARCHAR(255) NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS contacts (
    id SERIAL PRIMARY KEY,
    group_id INTEGER REFERENCES contact_groups(id) ON DELETE CASCADE,
    full_name VARCHAR(255),
    phone VARCHAR(50),
    metadata JSONB DEFAULT '{}', -- כאן יישמר כל המידע הנוסף מהעמודות הדינמיות
    source_file_id INTEGER REFERENCES uploaded_files(id),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_contacts_phone_group ON contacts(phone, group_id);
