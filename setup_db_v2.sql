-- VCF Manager Pro - Enhanced Schema v2.0

-- טבלת קבצים שהועלו
CREATE TABLE IF NOT EXISTS uploaded_files (
    id SERIAL PRIMARY KEY,
    original_name VARCHAR(500),
    file_path VARCHAR(500),
    file_size BIGINT DEFAULT 0,
    headers JSONB DEFAULT '[]',
    status VARCHAR(50) DEFAULT 'pending', -- pending, processed, archived
    parsed_count INT DEFAULT 0,
    valid_count INT DEFAULT 0,
    rejected_count INT DEFAULT 0,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- טבלת קבוצות אנשי קשר
CREATE TABLE IF NOT EXISTS contact_groups (
    id SERIAL PRIMARY KEY,
    name VARCHAR(255) NOT NULL,
    description TEXT,
    status VARCHAR(50) DEFAULT 'draft', -- draft, ready, archived
    version INT DEFAULT 1,
    parent_version_id INT REFERENCES contact_groups(id),
    draft_data JSONB,
    stats JSONB DEFAULT '{}', -- סטטיסטיקות מפורטות
    tags TEXT[] DEFAULT '{}',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- טבלת אנשי קשר
CREATE TABLE IF NOT EXISTS contacts (
    id SERIAL PRIMARY KEY,
    group_id INT REFERENCES contact_groups(id) ON DELETE CASCADE,
    full_name VARCHAR(500),
    phone VARCHAR(50),
    phone_normalized VARCHAR(50),
    email VARCHAR(255),
    source_file_id INT REFERENCES uploaded_files(id),
    source_file_name VARCHAR(500),
    original_data JSONB DEFAULT '{}', -- כל הנתונים המקוריים מה-VCF
    metadata JSONB DEFAULT '{}',
    tags TEXT[] DEFAULT '{}',
    is_duplicate BOOLEAN DEFAULT FALSE,
    duplicate_of INT REFERENCES contacts(id),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- טבלת אנשי קשר שנדחו
CREATE TABLE IF NOT EXISTS rejected_contacts (
    id SERIAL PRIMARY KEY,
    group_id INT REFERENCES contact_groups(id) ON DELETE CASCADE,
    source_file_id INT REFERENCES uploaded_files(id),
    source_file_name VARCHAR(500),
    full_name VARCHAR(500),
    phone_raw VARCHAR(255),
    rejection_reason VARCHAR(100), -- empty_phone, invalid_phone, too_short, duplicate, etc.
    original_data JSONB DEFAULT '{}',
    can_be_fixed BOOLEAN DEFAULT TRUE,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- טבלת גרסאות (היסטוריה)
CREATE TABLE IF NOT EXISTS group_versions (
    id SERIAL PRIMARY KEY,
    group_id INT REFERENCES contact_groups(id) ON DELETE CASCADE,
    version_number INT NOT NULL,
    version_name VARCHAR(255),
    description TEXT,
    contacts_snapshot JSONB, -- snapshot של כל אנשי הקשר
    stats JSONB,
    created_by VARCHAR(255) DEFAULT 'system',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- טבלת החלטות מיזוג (לזכור העדפות המשתמש)
CREATE TABLE IF NOT EXISTS import_resolutions (
    phone VARCHAR(50) PRIMARY KEY,
    resolved_name VARCHAR(500),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- טבלת תגיות
CREATE TABLE IF NOT EXISTS tags (
    id SERIAL PRIMARY KEY,
    name VARCHAR(100) UNIQUE NOT NULL,
    color VARCHAR(20) DEFAULT '#6366f1',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- טבלת שמות לא תקינים (blacklist)
CREATE TABLE IF NOT EXISTS invalid_names (
    id SERIAL PRIMARY KEY,
    name VARCHAR(500) NOT NULL,
    pattern_type VARCHAR(50) DEFAULT 'exact', -- exact, contains, regex
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(name, pattern_type)
);

-- טבלת הגדרות מערכת
CREATE TABLE IF NOT EXISTS system_settings (
    key VARCHAR(100) PRIMARY KEY,
    value JSONB NOT NULL,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- הגדרות ברירת מחדל לכללי בחירת שמות
INSERT INTO system_settings (key, value) VALUES 
('name_rules', '{
    "preferLonger": true,
    "maxLength": 20,
    "preferHebrew": true,
    "avoidSpecialChars": true,
    "allowedChars": ["''", "\"", "-", " "],
    "preferNoNumbers": true
}'::jsonb)
ON CONFLICT (key) DO NOTHING;

-- שמות לא תקינים ברירת מחדל
INSERT INTO invalid_names (name, pattern_type) VALUES 
('.', 'exact'),
('..', 'exact'),
('Unknown', 'exact'),
('No Name', 'exact'),
('ללא שם', 'exact'),
('אין שם', 'exact')
ON CONFLICT DO NOTHING;

-- אינדקסים לביצועים
CREATE INDEX IF NOT EXISTS idx_contacts_group ON contacts(group_id);
CREATE INDEX IF NOT EXISTS idx_contacts_phone ON contacts(phone_normalized);
CREATE INDEX IF NOT EXISTS idx_contacts_name ON contacts(full_name);
CREATE INDEX IF NOT EXISTS idx_rejected_group ON rejected_contacts(group_id);
CREATE INDEX IF NOT EXISTS idx_versions_group ON group_versions(group_id);

-- פונקציה לעדכון updated_at
CREATE OR REPLACE FUNCTION update_updated_at_column()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = CURRENT_TIMESTAMP;
    RETURN NEW;
END;
$$ language 'plpgsql';

-- טריגר לעדכון אוטומטי
DROP TRIGGER IF EXISTS update_contact_groups_updated_at ON contact_groups;
CREATE TRIGGER update_contact_groups_updated_at
    BEFORE UPDATE ON contact_groups
    FOR EACH ROW
    EXECUTE FUNCTION update_updated_at_column();

-- הוספת עמודות חדשות לטבלאות קיימות (migration)
DO $$ 
BEGIN
    -- uploaded_files
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name='uploaded_files' AND column_name='file_size') THEN
        ALTER TABLE uploaded_files ADD COLUMN file_size BIGINT DEFAULT 0;
    END IF;
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name='uploaded_files' AND column_name='parsed_count') THEN
        ALTER TABLE uploaded_files ADD COLUMN parsed_count INT DEFAULT 0;
    END IF;
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name='uploaded_files' AND column_name='valid_count') THEN
        ALTER TABLE uploaded_files ADD COLUMN valid_count INT DEFAULT 0;
    END IF;
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name='uploaded_files' AND column_name='rejected_count') THEN
        ALTER TABLE uploaded_files ADD COLUMN rejected_count INT DEFAULT 0;
    END IF;
    
    -- contact_groups
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name='contact_groups' AND column_name='description') THEN
        ALTER TABLE contact_groups ADD COLUMN description TEXT;
    END IF;
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name='contact_groups' AND column_name='version') THEN
        ALTER TABLE contact_groups ADD COLUMN version INT DEFAULT 1;
    END IF;
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name='contact_groups' AND column_name='stats') THEN
        ALTER TABLE contact_groups ADD COLUMN stats JSONB DEFAULT '{}';
    END IF;
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name='contact_groups' AND column_name='tags') THEN
        ALTER TABLE contact_groups ADD COLUMN tags TEXT[] DEFAULT '{}';
    END IF;
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name='contact_groups' AND column_name='updated_at') THEN
        ALTER TABLE contact_groups ADD COLUMN updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP;
    END IF;
    
    -- contacts
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name='contacts' AND column_name='phone_normalized') THEN
        ALTER TABLE contacts ADD COLUMN phone_normalized VARCHAR(50);
    END IF;
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name='contacts' AND column_name='email') THEN
        ALTER TABLE contacts ADD COLUMN email VARCHAR(255);
    END IF;
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name='contacts' AND column_name='source_file_name') THEN
        ALTER TABLE contacts ADD COLUMN source_file_name VARCHAR(500);
    END IF;
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name='contacts' AND column_name='original_data') THEN
        ALTER TABLE contacts ADD COLUMN original_data JSONB DEFAULT '{}';
    END IF;
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name='contacts' AND column_name='tags') THEN
        ALTER TABLE contacts ADD COLUMN tags TEXT[] DEFAULT '{}';
    END IF;
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name='contacts' AND column_name='is_duplicate') THEN
        ALTER TABLE contacts ADD COLUMN is_duplicate BOOLEAN DEFAULT FALSE;
    END IF;
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name='contacts' AND column_name='duplicate_of') THEN
        ALTER TABLE contacts ADD COLUMN duplicate_of INT REFERENCES contacts(id);
    END IF;
END $$;
