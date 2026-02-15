const express = require('express');
const multer = require('multer');
const { Pool } = require('pg');
const fs = require('fs');
const path = require('path');
const session = require('express-session');
const csv = require('csv-parser');

const app = express();
const uploadsDir = path.join(__dirname, 'storage/uploads');
if (!fs.existsSync(uploadsDir)) fs.mkdirSync(uploadsDir, { recursive: true });

const storage = multer.diskStorage({
    destination: (req, file, cb) => cb(null, uploadsDir),
    filename: (req, file, cb) => cb(null, Date.now() + '-' + file.originalname)
});
const upload = multer({ storage: storage });

const pool = new Pool({ 
    user: 'postgres', host: '127.0.0.1', database: 'vcf_db', 
    password: 'BotomatAdmin2025', port: 3378 
});

app.use(express.json({limit: '350mb'}));
app.use(session({ secret: 'vcf-luxury-elite-v8-final', resave: true, saveUninitialized: false, cookie: { maxAge: 24 * 60 * 60 * 1000 } }));

const auth = (req, res, next) => {
    if (req.session && req.session.authenticated) return next();
    if (req.path.startsWith('/api')) return res.status(401).json({ error: 'Session Expired' });
    res.redirect('/login');
};

const getBaseName = (name) => {
    if (!name) return '';
    return name.toString().replace(/\s?[\(\-]?\d+[\)]?$/g, '').trim();
};

const cleanName = (name) => {
    if (!name) return '';
    let n = name.toString().trim();
    n = n.replace(/\s?[\(\-]\d+[\)]?$/g, ''); 
    if (/^[\.\-\_\*\s\d]+$/.test(n)) return ''; 
    n = n.replace(/[\-\Reference\Reference\Reference\.\*]{2,}/g, ' ');
    n = n.replace(/[^א-תa-zA-Z0-9\s\'\"\-\(\)]/g, ' ');
    return n.replace(/\s\s+/g, ' ').trim();
};

const normalizePhone = (p) => {
    if(!p) return null;
    let c = p.toString().replace(/\D/g, '');
    if(c.startsWith('05')) c = '972' + c.substring(1);
    else if(c.length === 9 && c.startsWith('5')) c = '972' + c;
    return (c.length >= 9 && c.length <= 15) ? c : null;
};

function parseVcf(content) {
    const contacts = [];
    // פיצול לפי כרטיסים
    content.split(/BEGIN:VCARD/gi).forEach(card => {
        if (!card.includes('END:VCARD')) return;
        let entry = { 'Name': '', 'Phone': '' };
        
        // ניקוי שורות מקופלות (Line Folding) וחיבור שורות QP
        const cleanCard = card.replace(/=\r?\n/g, '').replace(/\r?\n\s/g, ' ');
        const lines = cleanCard.split(/\r?\n/);

        lines.forEach(line => {
            const upper = line.toUpperCase().trim();
            // טיפול בשדות שם (גם FN וגם N)
            if (upper.startsWith('FN') || upper.startsWith('N')) {
                const isFN = upper.startsWith('FN');
                let val = line.substring(line.indexOf(':') + 1).trim();
                
                // פענוח Quoted-Printable אם קיים
                if (upper.includes('QUOTED-PRINTABLE')) {
                    try {
                        // החלפת = ב-% לצורך פענוח URI
                        val = decodeURIComponent(val.replace(/=/g, '%'));
                    } catch(e) {
                        // פולבק במקרה של שגיאה
                        val = val.replace(/=[0-9A-F]{2}/gi, '');
                    }
                }
                
                // אם זה שדה N (Last;First;...), ננקה את ה-Semicolons
                if (!isFN) {
                    val = val.split(';').filter(part => part.trim()).join(' ');
                }
                
                // FN מקבל עדיפות, אם אין FN ניקח את ה-N
                if (isFN || !entry['Name']) entry['Name'] = val;
            } else if (upper.startsWith('TEL')) {
                entry['Phone'] = line.substring(line.lastIndexOf(':') + 1).replace(/\D/g, '');
            }
        });
        
        if (entry.Phone || entry.Name) contacts.push(entry);
    });
    return contacts;
}

app.get('/login', (req, res) => res.sendFile(path.join(__dirname, 'login.html')));
app.post('/login', (req, res) => {
    if (req.body.email === 'office@neriyabudraham.co.il') { req.session.authenticated = true; return res.json({ success: true }); }
    res.status(401).send();
});
app.get('/', auth, (req, res) => res.sendFile(path.join(__dirname, 'index.html')));

app.post('/api/upload', auth, upload.single('file'), async (req, res) => {
    try {
        const originalName = Buffer.from(req.file.originalname, 'latin1').toString('utf8');
        let rows = [];
        if (req.file.originalname.toLowerCase().endsWith('.vcf')) {
            rows = parseVcf(fs.readFileSync(req.file.path, 'utf8'));
        } else {
            const stream = fs.createReadStream(req.file.path).pipe(csv());
            for await (const row of stream) { rows.push(row); if(rows.length > 300) break; }
        }
        const headers = rows.length > 0 ? Object.keys(rows[0]) : [];
        const dbFile = await pool.query('INSERT INTO uploaded_files (original_name, file_path, headers) VALUES ($1, $2, $3) RETURNING id, original_name, headers', [originalName, req.file.path, JSON.stringify(headers)]);
        res.json({ ...dbFile.rows[0], sample: rows.slice(0, 10) });
    } catch (err) { res.status(500).json({ error: err.message }); }
});

app.get('/api/files', auth, async (req, res) => {
    const r = await pool.query("SELECT * FROM uploaded_files WHERE status = 'pending' ORDER BY id DESC");
    res.json(r.rows);
});

app.post('/api/analyze', auth, async (req, res) => {
    const { processingData, defaultName, startSerial, groupId, targetGroupName } = req.body;
    const draftRes = await pool.query('SELECT phone, resolved_name FROM import_resolutions');
    const drafts = new Map(draftRes.rows.map(r => [r.phone, r.resolved_name]));
    let responseData;

    if (groupId) {
        const g = await pool.query('SELECT draft_data, name FROM contact_groups WHERE id = $1', [groupId]);
        responseData = g.rows[0].draft_data;
        responseData.targetGroupName = g.rows[0].name;
    } else {
        const phoneMap = new Map();
        const conflicts = [];
        const autoResolved = [];
        let serial = parseInt(startSerial) || 1;

        for (const item of processingData) {
            const fileRes = await pool.query('SELECT * FROM uploaded_files WHERE id = $1', [item.fileId]);
            if (!fileRes.rows[0]) continue;
            const file = fileRes.rows[0];
            let rows = file.file_path.toLowerCase().endsWith('.vcf') ? parseVcf(fs.readFileSync(file.file_path, 'utf8')) : [];
            if (!file.file_path.toLowerCase().endsWith('.vcf')) {
                const stream = fs.createReadStream(file.file_path).pipe(csv());
                for await (const row of stream) rows.push(row);
            }

            rows.forEach(row => {
                const phone = normalizePhone(row[item.mapping.phoneField]);
                if (!phone) return;
                let name = cleanName(item.mapping.nameFields.map(f => row[f] || '').join(' '));
                if (!name) name = `${defaultName || 'איש קשר'} ${serial++}`;

                if (phoneMap.has(phone)) {
                    const existing = phoneMap.get(phone);
                    if (getBaseName(existing) === getBaseName(name)) {
                        const bestName = existing.length >= name.length ? existing : name;
                        phoneMap.set(phone, bestName);
                        if (!autoResolved.find(a => a.phone === phone)) autoResolved.push({ phone, name: bestName });
                    } else if (existing !== name) {
                        let conf = conflicts.find(c => c.phone === phone);
                        if (!conf) conflicts.push({ phone, names: [existing, name] });
                        else if (!conf.names.includes(name)) conf.names.push(name);
                    }
                } else phoneMap.set(phone, name);
            });
        }

        responseData = { 
            conflicts, 
            autoResolved, 
            allData: Array.from(phoneMap.entries()).map(([p, name]) => ({phone: p, name})),
            fileIds: processingData.map(d => d.fileId),
            targetGroupName: targetGroupName || 'ייבוא חדש'
        };

        const g = await pool.query("INSERT INTO contact_groups (name, status, draft_data) VALUES ($1, 'draft', $2) RETURNING id", [responseData.targetGroupName, JSON.stringify(responseData)]);
        responseData.groupId = g.rows[0].id;
    }
    res.json({ ...responseData, groupId: responseData.groupId || groupId });
});

app.post('/api/resolve', auth, async (req, res) => {
    const { phone, name } = req.body;
    await pool.query('INSERT INTO import_resolutions (phone, resolved_name) VALUES ($1, $2) ON CONFLICT (phone) DO UPDATE SET resolved_name = $2', [phone, name]);
    res.json({ success: true });
});

app.post('/api/finalize', auth, async (req, res) => {
    const { groupId, groupName, contacts, fileIds } = req.body;
    const resolutions = await pool.query('SELECT phone, resolved_name FROM import_resolutions');
    const resMap = new Map(resolutions.rows.map(r => [r.phone, r.resolved_name]));

    const finalContacts = [];
    const nameUsedRegistry = new Map();

    contacts.forEach(c => {
        let name = resMap.get(c.phone) || c.name;
        if (nameUsedRegistry.has(name)) {
            let count = nameUsedRegistry.get(name) + 1;
            nameUsedRegistry.set(name, count);
            name = `${name} (${count})`;
        } else { nameUsedRegistry.set(name, 1); }
        finalContacts.push({ phone: c.phone, name: name });
    });

    await pool.query("UPDATE contact_groups SET name = $1, status = 'ready', draft_data = NULL WHERE id = $2", [groupName, groupId]);
    let batch = [];
    for (const c of finalContacts) {
        batch.push([groupId, c.name, c.phone, '{}']);
        if (batch.length >= 2000) {
            await pool.query('INSERT INTO contacts (group_id, full_name, phone, metadata) SELECT * FROM UNNEST ($1::int[], $2::text[], $3::text[], $4::jsonb[])', [batch.map(r=>r[0]), batch.map(r=>r[1]), batch.map(r=>r[2]), batch.map(r=>r[3])]);
            batch = [];
        }
    }
    if (batch.length > 0) await pool.query('INSERT INTO contacts (group_id, full_name, phone, metadata) SELECT * FROM UNNEST ($1::int[], $2::text[], $3::text[], $4::jsonb[])', [batch.map(r=>r[0]), batch.map(r=>r[1]), batch.map(r=>r[2]), batch.map(r=>r[3])]);
    if (fileIds && fileIds.length > 0) await pool.query("UPDATE uploaded_files SET status = 'processed' WHERE id = ANY($1)", [fileIds]);
    await pool.query("TRUNCATE TABLE import_resolutions");
    res.json({ success: true });
});

app.get('/api/groups', auth, async (req, res) => {
    const r = await pool.query(`
        SELECT g.*, 
        CASE 
            WHEN g.status = 'draft' THEN jsonb_array_length(g.draft_data->'allData')
            ELSE (SELECT count(*) FROM contacts WHERE group_id = g.id) 
        END as count 
        FROM contact_groups g 
        ORDER BY CASE WHEN g.status = 'draft' THEN 0 ELSE 1 END, g.id DESC
    `);
    res.json(r.rows);
});

app.get('/api/groups/:id/contacts', auth, async (req, res) => {
    const r = await pool.query('SELECT full_name, phone FROM contacts WHERE group_id = $1 ORDER BY full_name ASC', [req.params.id]);
    res.json(r.rows);
});

app.delete('/api/groups/:id', auth, async (req, res) => {
    await pool.query('DELETE FROM contact_groups WHERE id = $1', [req.params.id]);
    res.json({ success: true });
});

app.delete('/api/files/:id', auth, async (req, res) => {
    const fRes = await pool.query('DELETE FROM uploaded_files WHERE id = $1 RETURNING file_path', [req.params.id]);
    if (fRes.rows[0] && fs.existsSync(fRes.rows[0].file_path)) fs.unlinkSync(fRes.rows[0].file_path);
    res.json({ success: true });
});

app.get('/api/export/:type/:id', auth, async (req, res) => {
    const r = await pool.query('SELECT full_name, phone FROM contacts WHERE group_id = $1', [req.params.id]);
    let out = (req.params.type === 'csv') ? "Name,Phone\n" : "";
    r.rows.forEach(c => {
        if (req.params.type === 'csv') out += `"${c.full_name}","${c.phone}"\n`;
        else out += `BEGIN:VCARD\nVERSION:3.0\nFN:${c.full_name}\nTEL;TYPE=CELL:${c.phone}\nEND:VCARD\n`;
    });
    res.setHeader('Content-Type', req.params.type === 'csv' ? 'text/csv' : 'text/vcard');
    res.setHeader('Content-Disposition', `attachment; filename=contacts.${req.params.type}`);
    res.send(out);
});

app.listen(3377);
