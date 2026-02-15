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
    user: process.env.DB_USER || 'postgres', 
    host: process.env.DB_HOST || '127.0.0.1', 
    database: process.env.DB_NAME || 'vcf_db', 
    password: process.env.DB_PASSWORD || 'BotomatAdmin2025', 
    port: parseInt(process.env.DB_PORT) || 3378 
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
    if(!c || c.length < 7) return null; // מינימום 7 ספרות (כולל קידומת)
    
    // נרמול מספרים ישראליים
    if(c.startsWith('05')) c = '972' + c.substring(1);
    else if(c.startsWith('5') && c.length === 9) c = '972' + c;
    else if(c.startsWith('9725') && c.length === 12) { /* כבר מנורמל */ }
    else if(c.startsWith('00972')) c = '972' + c.substring(5);
    else if(c.startsWith('+972')) c = '972' + c.substring(4);
    
    return (c.length >= 7 && c.length <= 15) ? c : null;
};

function parseVcf(content) {
    const contacts = [];
    
    // נרמול סופי שורות - המרה לפורמט אחיד
    content = content.replace(/\r\n/g, '\n').replace(/\r/g, '\n');
    
    // פיצול לפי כרטיסים
    const cards = content.split(/^BEGIN:VCARD$/gim);
    
    for (const card of cards) {
        if (!card.includes('END:VCARD')) continue;
        
        // חיבור שורות מקופלות (Line Folding - RFC 6350)
        // סוג 1: שורה שמתחילה ברווח או טאב היא המשך של הקודמת
        // סוג 2: Quoted-Printable - שורה שמסתיימת ב-= ממשיכה בשורה הבאה
        let unfoldedCard = card
            .replace(/=\n/g, '')           // QP soft line break
            .replace(/\n[ \t]/g, '');      // Standard vCard line folding
        
        const lines = unfoldedCard.split('\n');
        let entry = { 'Name': '', 'Phone': '' };
        let phones = [];

        for (const line of lines) {
            const trimmed = line.trim();
            if (!trimmed) continue;
            
            const upper = trimmed.toUpperCase();
            
            // בדיקה ספציפית לשדה FN (Full Name)
            if (upper.startsWith('FN:') || upper.startsWith('FN;')) {
                let val = trimmed.substring(trimmed.indexOf(':') + 1).trim();
                val = decodeVcfValue(val, upper);
                if (val) entry['Name'] = val;
            }
            // בדיקה ספציפית לשדה N (Name components) - רק אם מתחיל ב-N: או N;
            else if ((upper.startsWith('N:') || upper.startsWith('N;')) && !upper.startsWith('NOTE') && !upper.startsWith('NICKNAME')) {
                let val = trimmed.substring(trimmed.indexOf(':') + 1).trim();
                val = decodeVcfValue(val, upper);
                // N הוא בפורמט: Last;First;Middle;Prefix;Suffix
                val = val.split(';').filter(part => part.trim()).join(' ');
                // N משמש רק אם אין FN
                if (val && !entry['Name']) entry['Name'] = val;
            }
            // טיפול בטלפונים - איסוף כל המספרים
            else if (upper.startsWith('TEL:') || upper.startsWith('TEL;')) {
                let phoneVal = trimmed.substring(trimmed.lastIndexOf(':') + 1);
                phoneVal = phoneVal.replace(/[^\d+]/g, ''); // שמור רק ספרות ו-+
                if (phoneVal) phones.push(phoneVal);
            }
        }
        
        // בחר את הטלפון הראשון שנראה תקין (מעדיף מספרים ישראליים)
        entry['Phone'] = phones.find(p => /^(\+?972|05)/.test(p)) || phones[0] || '';
        
        if (entry.Phone || entry.Name) {
            contacts.push(entry);
        }
    }
    
    return contacts;
}

// פונקציה לפענוח ערכים מקודדים (Quoted-Printable, Base64)
function decodeVcfValue(val, upperLine) {
    if (!val) return '';
    
    // פענוח Quoted-Printable
    if (upperLine.includes('QUOTED-PRINTABLE') || upperLine.includes('ENCODING=QP')) {
        try {
            // שלב 1: החלפת כל =XX ל-%XX
            const percentEncoded = val.replace(/=([0-9A-F]{2})/gi, '%$1');
            // שלב 2: פענוח כל המחרוזת ביחד (חשוב ל-UTF-8 מרובה בתים)
            val = decodeURIComponent(percentEncoded);
        } catch(e) {
            // פולבק: נסה לפענח בחלקים
            try {
                val = val.replace(/=([0-9A-F]{2})/gi, (match, hex) => {
                    try {
                        return String.fromCharCode(parseInt(hex, 16));
                    } catch (e) {
                        return '';
                    }
                });
            } catch(e2) {
                // אם הכל נכשל, פשוט נקה את הקידוד
                val = val.replace(/=[0-9A-F]{2}/gi, '');
            }
        }
    }
    
    return val.trim();
}

app.get('/login', (req, res) => res.sendFile(path.join(__dirname, 'login.html')));
app.post('/login', (req, res) => {
    if (req.body.email === 'office@neriyabudraham.co.il') { req.session.authenticated = true; return res.json({ success: true }); }
    res.status(401).send();
});
app.get('/', auth, (req, res) => res.sendFile(path.join(__dirname, 'index.html')));

// Upload עם SSE לפרוגרס בזמן אמת
app.post('/api/upload', auth, upload.single('file'), async (req, res) => {
    try {
        const originalName = Buffer.from(req.file.originalname, 'latin1').toString('utf8');
        let rows = [];
        let parsedCount = 0;
        
        console.log(`[UPLOAD] Processing file: ${originalName}`);
        
        if (req.file.originalname.toLowerCase().endsWith('.vcf')) {
            const content = fs.readFileSync(req.file.path, 'utf8');
            rows = parseVcf(content);
            parsedCount = rows.length;
            console.log(`[UPLOAD] VCF parsed: ${parsedCount} contacts`);
        } else {
            const stream = fs.createReadStream(req.file.path).pipe(csv());
            for await (const row of stream) { 
                rows.push(row); 
                parsedCount++;
            }
            console.log(`[UPLOAD] CSV parsed: ${parsedCount} rows`);
        }
        
        const headers = rows.length > 0 ? Object.keys(rows[0]) : [];
        const dbFile = await pool.query('INSERT INTO uploaded_files (original_name, file_path, headers) VALUES ($1, $2, $3) RETURNING id, original_name, headers', [originalName, req.file.path, JSON.stringify(headers)]);
        
        res.json({ 
            ...dbFile.rows[0], 
            sample: rows.slice(0, 10),
            parsedCount 
        });
    } catch (err) { 
        console.error(`[UPLOAD] Error:`, err);
        res.status(500).json({ error: err.message }); 
    }
});

// SSE endpoint לפרוגרס עיבוד בזמן אמת
app.get('/api/upload-progress/:uploadId', auth, (req, res) => {
    res.setHeader('Content-Type', 'text/event-stream');
    res.setHeader('Cache-Control', 'no-cache');
    res.setHeader('Connection', 'keep-alive');
    
    const uploadId = req.params.uploadId;
    
    // שמור את ה-response לעדכונים
    if (!global.uploadProgress) global.uploadProgress = {};
    global.uploadProgress[uploadId] = res;
    
    req.on('close', () => {
        delete global.uploadProgress[uploadId];
    });
});

// פונקציה לשליחת עדכון פרוגרס
function sendProgress(uploadId, percent, message) {
    if (global.uploadProgress && global.uploadProgress[uploadId]) {
        global.uploadProgress[uploadId].write(`data: ${JSON.stringify({ percent, message })}\n\n`);
    }
}

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

        // לוגים לדיבוג
        let totalParsed = 0;
        let totalValidPhones = 0;
        let totalSkippedNoPhone = 0;

        for (const item of processingData) {
            const fileRes = await pool.query('SELECT * FROM uploaded_files WHERE id = $1', [item.fileId]);
            if (!fileRes.rows[0]) {
                console.log(`[ANALYZE] File ID ${item.fileId} not found in DB`);
                continue;
            }
            const file = fileRes.rows[0];
            
            console.log(`[ANALYZE] Processing file: ${file.original_name}`);
            console.log(`[ANALYZE] Mapping: phoneField=${item.mapping?.phoneField}, nameFields=${JSON.stringify(item.mapping?.nameFields)}`);
            
            let rows = [];
            if (file.file_path.toLowerCase().endsWith('.vcf')) {
                rows = parseVcf(fs.readFileSync(file.file_path, 'utf8'));
            } else {
                const stream = fs.createReadStream(file.file_path).pipe(csv());
                for await (const row of stream) rows.push(row);
            }
            
            console.log(`[ANALYZE] Parsed ${rows.length} rows from file`);
            totalParsed += rows.length;
            
            // בדוק את ה-mapping
            if (!item.mapping || !item.mapping.phoneField) {
                console.log(`[ANALYZE] WARNING: Missing mapping for file ${file.id}`);
                continue;
            }

            let fileValidPhones = 0;
            let fileSkipped = 0;
            let skippedExamples = [];
            
            rows.forEach(row => {
                const rawPhone = row[item.mapping.phoneField];
                const phone = normalizePhone(rawPhone);
                
                if (!phone) {
                    fileSkipped++;
                    // שמור דוגמאות למספרים שנדחו
                    if (skippedExamples.length < 10) {
                        skippedExamples.push({ name: row[item.mapping.nameFields?.[0]] || '', phone: rawPhone || '(ריק)' });
                    }
                    return;
                }
                
                fileValidPhones++;
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
            
            console.log(`[ANALYZE] File stats: validPhones=${fileValidPhones}, skipped=${fileSkipped}`);
            if (skippedExamples.length > 0) {
                console.log(`[ANALYZE] Skipped examples:`, skippedExamples);
            }
            totalValidPhones += fileValidPhones;
            totalSkippedNoPhone += fileSkipped;
        }

        console.log(`[ANALYZE] TOTAL: parsed=${totalParsed}, validPhones=${totalValidPhones}, skipped=${totalSkippedNoPhone}`);
        console.log(`[ANALYZE] Unique phones in map: ${phoneMap.size}`);
        console.log(`[ANALYZE] Conflicts: ${conflicts.length}, AutoResolved: ${autoResolved.length}`);

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

// בדיקת בריאות ופרסר
app.get('/api/health', (req, res) => {
    res.json({ status: 'ok', timestamp: new Date().toISOString() });
});

// בדיקת פרסר VCF על קובץ קיים
app.get('/api/test-parse/:fileId', auth, async (req, res) => {
    try {
        const fileRes = await pool.query('SELECT * FROM uploaded_files WHERE id = $1', [req.params.fileId]);
        if (!fileRes.rows[0]) return res.status(404).json({ error: 'File not found' });
        
        const file = fileRes.rows[0];
        const content = fs.readFileSync(file.file_path, 'utf8');
        const actualVcards = (content.match(/BEGIN:VCARD/gi) || []).length;
        
        const parsed = parseVcf(content);
        const validPhones = parsed.filter(c => normalizePhone(c.Phone)).length;
        
        res.json({
            fileName: file.original_name,
            fileSize: content.length,
            actualVcards,
            parsedContacts: parsed.length,
            validPhones,
            sample: parsed.slice(0, 10)
        });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

app.listen(3377, () => {
    console.log('[VCF Server] Running on port 3377');
});
