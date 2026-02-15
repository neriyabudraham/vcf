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
const upload = multer({ storage: storage, limits: { fileSize: 100 * 1024 * 1024 } }); // 100MB max

const pool = new Pool({ 
    user: process.env.DB_USER || 'postgres', 
    host: process.env.DB_HOST || '127.0.0.1', 
    database: process.env.DB_NAME || 'vcf_db', 
    password: process.env.DB_PASSWORD || 'BotomatAdmin2025', 
    port: parseInt(process.env.DB_PORT) || 3378 
});

app.use(express.json({limit: '350mb'}));
app.use(express.static(__dirname));
app.use(session({ secret: 'vcf-luxury-elite-v8-final', resave: true, saveUninitialized: false, cookie: { maxAge: 24 * 60 * 60 * 1000 } }));

const auth = (req, res, next) => {
    if (req.session && req.session.authenticated) return next();
    if (req.path.startsWith('/api')) return res.status(401).json({ error: 'Session Expired' });
    res.redirect('/login');
};

// ==================== UTILITY FUNCTIONS ====================

const normalizePhone = (p) => {
    if(!p) return { normalized: null, reason: 'empty_phone' };
    let c = p.toString().replace(/\D/g, '');
    if(!c || c.length === 0) return { normalized: null, reason: 'empty_phone' };
    if(c.length < 7) return { normalized: null, reason: 'too_short', original: c };
    if(c.length > 15) return { normalized: null, reason: 'too_long', original: c };
    
    // נרמול מספרים ישראליים
    if(c.startsWith('05')) c = '972' + c.substring(1);
    else if(c.startsWith('5') && c.length === 9) c = '972' + c;
    else if(c.startsWith('00972')) c = '972' + c.substring(5);
    else if(c.startsWith('972') && c.length >= 11) { /* כבר מנורמל */ }
    
    return { normalized: c, reason: null };
};

const getBaseName = (name) => {
    if (!name) return '';
    return name.toString().replace(/\s?\(\d+\)$/g, '').trim();
};

const cleanName = (name) => {
    if (!name) return '';
    let n = name.toString().trim();
    n = n.replace(/\s?\(\d+\)$/g, ''); 
    if (/^[\.\-\_\*\s\d]+$/.test(n)) return ''; 
    n = n.replace(/[^א-תa-zA-Z0-9\s\'\"\-\(\)\.]/g, ' ');
    return n.replace(/\s\s+/g, ' ').trim();
};

// בדיקה אם שם ברשימת השמות הלא תקינים
let invalidNamesCache = null;
async function loadInvalidNames() {
    try {
        const res = await pool.query('SELECT name, pattern_type FROM invalid_names');
        invalidNamesCache = res.rows;
    } catch (e) {
        invalidNamesCache = [];
    }
    return invalidNamesCache;
}

async function isInvalidName(name) {
    if (!name || name.trim() === '') return true;
    if (!invalidNamesCache) await loadInvalidNames();
    const normalized = name.trim().toLowerCase();
    for (const rule of invalidNamesCache) {
        if (rule.pattern_type === 'exact' && rule.name.toLowerCase() === normalized) return true;
        if (rule.pattern_type === 'contains' && normalized.includes(rule.name.toLowerCase())) return true;
        if (rule.pattern_type === 'regex') {
            try { if (new RegExp(rule.name, 'i').test(name)) return true; } catch(e) {}
        }
    }
    return false;
}

// טעינת כללי בחירת שמות
let nameRulesCache = null;
async function loadNameRules() {
    try {
        const res = await pool.query("SELECT value FROM system_settings WHERE key = 'name_rules'");
        nameRulesCache = res.rows[0]?.value || {};
    } catch (e) {
        nameRulesCache = { preferLonger: true, maxLength: 20, preferHebrew: true, avoidSpecialChars: true };
    }
    return nameRulesCache;
}

// חישוב ציון לשם (ככל שגבוה יותר - השם טוב יותר)
async function scoreName(name) {
    if (!name || name.trim() === '') return -1000;
    if (await isInvalidName(name)) return -1000;
    
    const rules = nameRulesCache || await loadNameRules();
    let score = 0;
    const n = name.trim();
    
    // אורך - עדיפות לארוך יותר אבל לא יותר מדי
    if (rules.preferLonger) {
        if (n.length <= (rules.maxLength || 20)) {
            score += n.length * 2;
        } else {
            score -= (n.length - rules.maxLength) * 3; // קנס על שם ארוך מדי
        }
    }
    
    // עדיפות לעברית
    if (rules.preferHebrew) {
        const hebrewChars = (n.match(/[א-ת]/g) || []).length;
        const totalChars = n.replace(/\s/g, '').length;
        if (hebrewChars > 0) {
            score += 30 + (hebrewChars / totalChars) * 20;
        }
    }
    
    // הימנעות מסימנים מיוחדים
    if (rules.avoidSpecialChars) {
        const allowed = rules.allowedChars || ["'", '"', "-", " "];
        const specialPattern = new RegExp(`[^א-תa-zA-Z0-9${allowed.map(c => '\\' + c).join('')}]`, 'g');
        const badChars = (n.match(specialPattern) || []).length;
        score -= badChars * 10;
    }
    
    // הימנעות ממספרים
    if (rules.preferNoNumbers) {
        const numbers = (n.match(/\d/g) || []).length;
        score -= numbers * 5;
    }
    
    // בונוס לשם עם רווח (שם + משפחה)
    if (n.includes(' ') && n.split(' ').length >= 2) {
        score += 15;
    }
    
    return score;
}

// בחירת השם הטוב ביותר מרשימה
async function chooseBestName(names) {
    if (!names || names.length === 0) return '';
    if (names.length === 1) return names[0];
    
    let bestName = names[0];
    let bestScore = await scoreName(names[0]);
    
    for (let i = 1; i < names.length; i++) {
        const s = await scoreName(names[i]);
        if (s > bestScore) {
            bestScore = s;
            bestName = names[i];
        }
    }
    
    return bestName;
}

// יצירת שם ייחודי עם (X) אם צריך
function makeUniqueName(name, existingNames) {
    if (!name) return name;
    const baseName = getBaseName(name);
    if (!existingNames.has(baseName.toLowerCase())) {
        existingNames.add(baseName.toLowerCase());
        return baseName;
    }
    
    let counter = 2;
    while (existingNames.has(`${baseName} (${counter})`.toLowerCase())) {
        counter++;
    }
    const uniqueName = `${baseName} (${counter})`;
    existingNames.add(uniqueName.toLowerCase());
    return uniqueName;
}

function parseVcf(content) {
    const contacts = [];
    content = content.replace(/\r\n/g, '\n').replace(/\r/g, '\n');
    const cards = content.split(/^BEGIN:VCARD$/gim);
    
    for (const card of cards) {
        if (!card.includes('END:VCARD')) continue;
        
        let unfoldedCard = card.replace(/=\n/g, '').replace(/\n[ \t]/g, '');
        const lines = unfoldedCard.split('\n');
        let entry = { Name: '', Phone: '', Email: '', OriginalData: {} };
        let phones = [];

        for (const line of lines) {
            const trimmed = line.trim();
            if (!trimmed) continue;
            const upper = trimmed.toUpperCase();
            
            if (upper.startsWith('FN:') || upper.startsWith('FN;')) {
                let val = trimmed.substring(trimmed.indexOf(':') + 1).trim();
                val = decodeVcfValue(val, upper);
                if (val) entry.Name = val;
            }
            else if ((upper.startsWith('N:') || upper.startsWith('N;')) && !upper.startsWith('NOTE') && !upper.startsWith('NICKNAME')) {
                let val = trimmed.substring(trimmed.indexOf(':') + 1).trim();
                val = decodeVcfValue(val, upper);
                val = val.split(';').filter(part => part.trim()).join(' ');
                if (val && !entry.Name) entry.Name = val;
            }
            else if (upper.startsWith('TEL:') || upper.startsWith('TEL;') || 
                     upper.match(/^ITEM\d*\.TEL/) || upper.startsWith('X-TEL') ||
                     upper.startsWith('X-PHONE') || upper.includes('.TEL:') || upper.includes('.TEL;')) {
                let phoneVal = trimmed.substring(trimmed.lastIndexOf(':') + 1);
                phoneVal = phoneVal.replace(/[^\d+]/g, '');
                if (phoneVal) phones.push(phoneVal);
                
                // שמור את כל הטלפונים ב-OriginalData
                if (!entry.OriginalData.phones) entry.OriginalData.phones = [];
                entry.OriginalData.phones.push(phoneVal);
            }
            else if (upper.startsWith('EMAIL:') || upper.startsWith('EMAIL;')) {
                let emailVal = trimmed.substring(trimmed.indexOf(':') + 1).trim();
                if (emailVal && !entry.Email) entry.Email = emailVal;
            }
            else if (upper.startsWith('ORG:') || upper.startsWith('ORG;')) {
                entry.OriginalData.organization = trimmed.substring(trimmed.indexOf(':') + 1).trim();
            }
            else if (upper.startsWith('NOTE:') || upper.startsWith('NOTE;')) {
                entry.OriginalData.note = decodeVcfValue(trimmed.substring(trimmed.indexOf(':') + 1).trim(), upper);
            }
        }
        
        entry.Phone = phones.find(p => /^(\+?972|05)/.test(p)) || phones[0] || '';
        if (entry.Phone || entry.Name) contacts.push(entry);
    }
    
    return contacts;
}

function decodeVcfValue(val, upperLine) {
    if (!val) return '';
    if (upperLine.includes('QUOTED-PRINTABLE') || upperLine.includes('ENCODING=QP')) {
        try {
            const percentEncoded = val.replace(/=([0-9A-F]{2})/gi, '%$1');
            val = decodeURIComponent(percentEncoded);
        } catch(e) {
            try {
                val = val.replace(/=([0-9A-F]{2})/gi, (match, hex) => {
                    try { return String.fromCharCode(parseInt(hex, 16)); } catch (e) { return ''; }
                });
            } catch(e2) {
                val = val.replace(/=[0-9A-F]{2}/gi, '');
            }
        }
    }
    return val.trim();
}

// ==================== AUTH ROUTES ====================

app.get('/login', (req, res) => res.sendFile(path.join(__dirname, 'login.html')));
app.post('/login', (req, res) => {
    if (req.body.email === 'office@neriyabudraham.co.il') { 
        req.session.authenticated = true; 
        return res.json({ success: true }); 
    }
    res.status(401).send();
});
app.get('/', auth, (req, res) => res.sendFile(path.join(__dirname, 'index.html')));

// ==================== UPLOAD & PARSE ====================

app.post('/api/upload', auth, upload.single('file'), async (req, res) => {
    try {
        const originalName = Buffer.from(req.file.originalname, 'latin1').toString('utf8');
        const fileSize = req.file.size;
        let rows = [];
        
        console.log(`[UPLOAD] Processing file: ${originalName} (${(fileSize/1024/1024).toFixed(2)} MB)`);
        
        if (req.file.originalname.toLowerCase().endsWith('.vcf')) {
            const content = fs.readFileSync(req.file.path, 'utf8');
            rows = parseVcf(content);
        } else {
            const stream = fs.createReadStream(req.file.path).pipe(csv());
            for await (const row of stream) rows.push(row);
        }
        
        // ניתוח מהיר של הנתונים
        let validCount = 0, rejectedCount = 0;
        const rejectionReasons = {};
        
        rows.forEach(row => {
            const phone = row.Phone || row.phone || row.TEL || '';
            const result = normalizePhone(phone);
            if (result.normalized) {
                validCount++;
            } else {
                rejectedCount++;
                rejectionReasons[result.reason] = (rejectionReasons[result.reason] || 0) + 1;
            }
        });
        
        console.log(`[UPLOAD] Parsed: ${rows.length}, Valid: ${validCount}, Rejected: ${rejectedCount}`);
        console.log(`[UPLOAD] Rejection reasons:`, rejectionReasons);
        
        const headers = rows.length > 0 ? Object.keys(rows[0]).filter(k => k !== 'OriginalData') : [];
        const dbFile = await pool.query(
            `INSERT INTO uploaded_files (original_name, file_path, file_size, headers, parsed_count, valid_count, rejected_count) 
             VALUES ($1, $2, $3, $4, $5, $6, $7) RETURNING *`,
            [originalName, req.file.path, fileSize, JSON.stringify(headers), rows.length, validCount, rejectedCount]
        );
        
        res.json({ 
            ...dbFile.rows[0], 
            sample: rows.slice(0, 10),
            stats: {
                total: rows.length,
                valid: validCount,
                rejected: rejectedCount,
                rejectionReasons
            }
        });
    } catch (err) { 
        console.error(`[UPLOAD] Error:`, err);
        res.status(500).json({ error: err.message }); 
    }
});

// ==================== FILES MANAGEMENT ====================

app.get('/api/files', auth, async (req, res) => {
    try {
        const r = await pool.query(`
            SELECT *, 
                   to_char(created_at, 'DD/MM/YYYY HH24:MI') as created_at_formatted
            FROM uploaded_files 
            WHERE status = 'pending' 
            ORDER BY id DESC
        `);
        res.json(r.rows);
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

app.delete('/api/files/:id', auth, async (req, res) => {
    try {
        const fRes = await pool.query('DELETE FROM uploaded_files WHERE id = $1 RETURNING file_path', [req.params.id]);
        if (fRes.rows[0] && fs.existsSync(fRes.rows[0].file_path)) fs.unlinkSync(fRes.rows[0].file_path);
        res.json({ success: true });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// ==================== ANALYZE & PROCESS ====================

app.post('/api/analyze', auth, async (req, res) => {
    const { processingData, defaultName, startSerial, groupId, targetGroupName, addToGroupId } = req.body;
    
    try {
        let responseData;

        if (groupId) {
            // טעינת טיוטה קיימת
            const g = await pool.query('SELECT draft_data, name FROM contact_groups WHERE id = $1', [groupId]);
            if (!g.rows[0]) return res.status(404).json({ error: 'Group not found' });
            responseData = g.rows[0].draft_data;
            responseData.targetGroupName = g.rows[0].name;
        } else {
            // עיבוד חדש
            const phoneMap = new Map();
            const conflicts = [];
            const autoResolved = [];
            const rejectedContacts = [];
            let serial = parseInt(startSerial) || 1;
            
            let totalStats = {
                totalParsed: 0,
                totalValid: 0,
                totalRejected: 0,
                totalDuplicates: 0,
                rejectionReasons: {},
                byFile: []
            };

            for (const item of processingData) {
                const fileRes = await pool.query('SELECT * FROM uploaded_files WHERE id = $1', [item.fileId]);
                if (!fileRes.rows[0]) continue;
                const file = fileRes.rows[0];
                
                console.log(`[ANALYZE] Processing: ${file.original_name}`);
                
                let rows = [];
                if (file.file_path.toLowerCase().endsWith('.vcf')) {
                    rows = parseVcf(fs.readFileSync(file.file_path, 'utf8'));
                } else {
                    const stream = fs.createReadStream(file.file_path).pipe(csv());
                    for await (const row of stream) rows.push(row);
                }
                
                let fileStats = { 
                    fileName: file.original_name, 
                    fileId: file.id,
                    total: rows.length, 
                    valid: 0, 
                    rejected: 0,
                    duplicates: 0,
                    rejectionReasons: {} 
                };
                
                for (const row of rows) {
                    const rawPhone = row[item.mapping.phoneField];
                    const phoneResult = normalizePhone(rawPhone);
                    
                    if (!phoneResult.normalized) {
                        fileStats.rejected++;
                        fileStats.rejectionReasons[phoneResult.reason] = (fileStats.rejectionReasons[phoneResult.reason] || 0) + 1;
                        totalStats.rejectionReasons[phoneResult.reason] = (totalStats.rejectionReasons[phoneResult.reason] || 0) + 1;
                        
                        // שמור את איש הקשר שנדחה
                        rejectedContacts.push({
                            name: item.mapping.nameFields.map(f => row[f] || '').join(' ').trim() || '(ללא שם)',
                            phone: rawPhone || '',
                            reason: phoneResult.reason,
                            sourceFile: file.original_name,
                            sourceFileId: file.id,
                            originalData: row.OriginalData || {}
                        });
                        continue;
                    }
                    
                    const phone = phoneResult.normalized;
                    let name = cleanName(item.mapping.nameFields.map(f => row[f] || '').join(' '));
                    if (!name) name = `${defaultName || 'איש קשר'} ${serial++}`;
                    
                    const contactData = {
                        name,
                        phone,
                        phoneRaw: rawPhone,
                        email: row.Email || row.email || '',
                        sourceFile: file.original_name,
                        sourceFileId: file.id,
                        originalData: row.OriginalData || {}
                    };

                    if (phoneMap.has(phone)) {
                        const existing = phoneMap.get(phone);
                        fileStats.duplicates++;
                        
                        if (getBaseName(existing.name) === getBaseName(name)) {
                            // שמות דומים - בחר את הטוב יותר לפי כללי הניקוד
                            const existingScore = await scoreName(existing.name);
                            const newScore = await scoreName(name);
                            const bestName = newScore > existingScore ? name : existing.name;
                            existing.name = bestName;
                            if (!autoResolved.find(a => a.phone === phone)) {
                                autoResolved.push({ phone, name: bestName, allNames: [existing.name, name], count: 2 });
                            } else {
                                const ar = autoResolved.find(a => a.phone === phone);
                                ar.count++;
                                if (!ar.allNames.includes(name)) ar.allNames.push(name);
                            }
                        } else if (existing.name !== name) {
                            // שמות שונים - קונפליקט (אלא אם נבחר אוטומטית)
                            const existingScore = await scoreName(existing.name);
                            const newScore = await scoreName(name);
                            
                            let conf = conflicts.find(c => c.phone === phone);
                            if (!conf) {
                                conf = { 
                                    phone, 
                                    names: [existing.name, name], 
                                    scores: [existingScore, newScore],
                                    sources: [existing.sourceFile, contactData.sourceFile],
                                    autoSelected: existingScore >= newScore ? existing.name : name
                                };
                                conflicts.push(conf);
                                // עדכן את השם שנבחר אוטומטית
                                if (newScore > existingScore) {
                                    existing.name = name;
                                }
                            } else if (!conf.names.includes(name)) {
                                conf.names.push(name);
                                conf.scores.push(newScore);
                                conf.sources.push(contactData.sourceFile);
                                // עדכן את הבחירה האוטומטית אם צריך
                                const maxScoreIdx = conf.scores.indexOf(Math.max(...conf.scores));
                                conf.autoSelected = conf.names[maxScoreIdx];
                                existing.name = conf.autoSelected;
                            }
                        }
                    } else {
                        phoneMap.set(phone, contactData);
                        fileStats.valid++;
                    }
                }
                
                totalStats.totalParsed += fileStats.total;
                totalStats.totalValid += fileStats.valid;
                totalStats.totalRejected += fileStats.rejected;
                totalStats.totalDuplicates += fileStats.duplicates;
                totalStats.byFile.push(fileStats);
                
                console.log(`[ANALYZE] File stats:`, fileStats);
            }

            console.log(`[ANALYZE] Total stats:`, totalStats);

            responseData = { 
                conflicts, 
                autoResolved, 
                rejectedContacts,
                allData: Array.from(phoneMap.values()),
                stats: totalStats,
                fileIds: processingData.map(d => d.fileId),
                targetGroupName: targetGroupName || 'ייבוא חדש'
            };

            // שמור כטיוטה
            const g = await pool.query(
                `INSERT INTO contact_groups (name, status, draft_data, stats) 
                 VALUES ($1, 'draft', $2, $3) RETURNING id`,
                [responseData.targetGroupName, JSON.stringify(responseData), JSON.stringify(totalStats)]
            );
            responseData.groupId = g.rows[0].id;
        }
        
        res.json({ ...responseData, groupId: responseData.groupId || groupId });
    } catch (err) {
        console.error('[ANALYZE] Error:', err);
        res.status(500).json({ error: err.message });
    }
});

// ==================== CONFLICT RESOLUTION ====================

app.post('/api/resolve', auth, async (req, res) => {
    try {
        const { phone, name } = req.body;
        await pool.query(
            'INSERT INTO import_resolutions (phone, resolved_name) VALUES ($1, $2) ON CONFLICT (phone) DO UPDATE SET resolved_name = $2', 
            [phone, name]
        );
        res.json({ success: true });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// ==================== FINALIZE GROUP ====================

app.post('/api/finalize', auth, async (req, res) => {
    const { groupId, groupName, contacts, fileIds, stats } = req.body;
    
    try {
        const resolutions = await pool.query('SELECT phone, resolved_name FROM import_resolutions');
        const resMap = new Map(resolutions.rows.map(r => [r.phone, r.resolved_name]));

        const finalContacts = [];
        const usedNames = new Set();

        for (const c of contacts) {
            let name = resMap.get(c.phone) || c.name;
            
            // בדיקה אם השם לא תקין - החלף בשם ברירת מחדל
            if (await isInvalidName(name)) {
                const baseName = getBaseName(name);
                name = baseName && !await isInvalidName(baseName) ? baseName : `איש קשר ${c.phone.slice(-4)}`;
            }
            
            // וודא שם ייחודי עם (X) אם צריך
            name = makeUniqueName(name, usedNames);
            
            finalContacts.push({ 
                phone: c.phone, 
                name, 
                email: c.email || '',
                sourceFile: c.sourceFile || '',
                sourceFileId: c.sourceFileId || null,
                originalData: c.originalData || {}
            });
        }

        // עדכון הקבוצה
        await pool.query(
            `UPDATE contact_groups SET name = $1, status = 'ready', draft_data = NULL, stats = $3, version = 1 WHERE id = $2`,
            [groupName, groupId, JSON.stringify(stats || {})]
        );
        
        // שמירת גרסה ראשונה
        await pool.query(
            `INSERT INTO group_versions (group_id, version_number, version_name, contacts_snapshot, stats) 
             VALUES ($1, 1, 'גרסה ראשונית', $2, $3)`,
            [groupId, JSON.stringify(finalContacts), JSON.stringify(stats || {})]
        );
        
        // הכנסת אנשי קשר (עם חיתוך ערכים ארוכים)
        const truncate = (s, max) => s && s.length > max ? s.substring(0, max) : s;
        let batch = [];
        for (const c of finalContacts) {
            batch.push([
                groupId, 
                truncate(c.name, 250), 
                c.phone, 
                c.phone, 
                truncate(c.email, 250), 
                c.sourceFileId, 
                truncate(c.sourceFile, 450), 
                JSON.stringify(c.originalData), 
                '{}'
            ]);
            if (batch.length >= 1000) {
                await pool.query(
                    `INSERT INTO contacts (group_id, full_name, phone, phone_normalized, email, source_file_id, source_file_name, original_data, metadata) 
                     SELECT * FROM UNNEST ($1::int[], $2::text[], $3::text[], $4::text[], $5::text[], $6::int[], $7::text[], $8::jsonb[], $9::jsonb[])`,
                    [batch.map(r=>r[0]), batch.map(r=>r[1]), batch.map(r=>r[2]), batch.map(r=>r[3]), batch.map(r=>r[4]), batch.map(r=>r[5]), batch.map(r=>r[6]), batch.map(r=>r[7]), batch.map(r=>r[8])]
                );
                batch = [];
            }
        }
        if (batch.length > 0) {
            await pool.query(
                `INSERT INTO contacts (group_id, full_name, phone, phone_normalized, email, source_file_id, source_file_name, original_data, metadata) 
                 SELECT * FROM UNNEST ($1::int[], $2::text[], $3::text[], $4::text[], $5::text[], $6::int[], $7::text[], $8::jsonb[], $9::jsonb[])`,
                [batch.map(r=>r[0]), batch.map(r=>r[1]), batch.map(r=>r[2]), batch.map(r=>r[3]), batch.map(r=>r[4]), batch.map(r=>r[5]), batch.map(r=>r[6]), batch.map(r=>r[7]), batch.map(r=>r[8])]
            );
        }
        
        // עדכון קבצים כמעובדים
        if (fileIds && fileIds.length > 0) {
            await pool.query("UPDATE uploaded_files SET status = 'processed' WHERE id = ANY($1)", [fileIds]);
        }
        
        await pool.query("TRUNCATE TABLE import_resolutions");
        res.json({ success: true, contactsCount: finalContacts.length });
    } catch (err) {
        console.error('[FINALIZE] Error:', err);
        res.status(500).json({ error: err.message });
    }
});

// ==================== GROUPS MANAGEMENT ====================

app.get('/api/groups', auth, async (req, res) => {
    try {
        const r = await pool.query(`
            SELECT g.*, 
                   CASE 
                       WHEN g.status = 'draft' THEN COALESCE(jsonb_array_length(g.draft_data->'allData'), 0)
                       ELSE (SELECT count(*) FROM contacts WHERE group_id = g.id) 
                   END as count,
                   to_char(g.created_at, 'DD/MM/YYYY HH24:MI') as created_at_formatted,
                   to_char(g.updated_at, 'DD/MM/YYYY HH24:MI') as updated_at_formatted
            FROM contact_groups g 
            ORDER BY CASE WHEN g.status = 'draft' THEN 0 ELSE 1 END, g.updated_at DESC
        `);
        res.json(r.rows);
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

app.get('/api/groups/:id', auth, async (req, res) => {
    try {
        const g = await pool.query('SELECT * FROM contact_groups WHERE id = $1', [req.params.id]);
        if (!g.rows[0]) return res.status(404).json({ error: 'Group not found' });
        
        const contacts = await pool.query(
            'SELECT * FROM contacts WHERE group_id = $1 ORDER BY full_name ASC',
            [req.params.id]
        );
        
        const versions = await pool.query(
            `SELECT id, version_number, version_name, stats, 
                    to_char(created_at, 'DD/MM/YYYY HH24:MI') as created_at_formatted
             FROM group_versions WHERE group_id = $1 ORDER BY version_number DESC`,
            [req.params.id]
        );
        
        res.json({
            ...g.rows[0],
            contacts: contacts.rows,
            versions: versions.rows
        });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

app.get('/api/groups/:id/contacts', auth, async (req, res) => {
    try {
        const { search, page = 1, limit = 100 } = req.query;
        const offset = (page - 1) * limit;
        
        let query = 'SELECT * FROM contacts WHERE group_id = $1';
        let params = [req.params.id];
        
        if (search) {
            query += ' AND (full_name ILIKE $2 OR phone ILIKE $2)';
            params.push(`%${search}%`);
        }
        
        query += ' ORDER BY full_name ASC LIMIT $' + (params.length + 1) + ' OFFSET $' + (params.length + 2);
        params.push(limit, offset);
        
        const r = await pool.query(query, params);
        
        // ספירה כוללת
        let countQuery = 'SELECT count(*) FROM contacts WHERE group_id = $1';
        let countParams = [req.params.id];
        if (search) {
            countQuery += ' AND (full_name ILIKE $2 OR phone ILIKE $2)';
            countParams.push(`%${search}%`);
        }
        const countRes = await pool.query(countQuery, countParams);
        
        res.json({
            contacts: r.rows,
            total: parseInt(countRes.rows[0].count),
            page: parseInt(page),
            limit: parseInt(limit)
        });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

app.delete('/api/groups/:id', auth, async (req, res) => {
    try {
        await pool.query('DELETE FROM group_versions WHERE group_id = $1', [req.params.id]);
        await pool.query('DELETE FROM contacts WHERE group_id = $1', [req.params.id]);
        await pool.query('DELETE FROM contact_groups WHERE id = $1', [req.params.id]);
        res.json({ success: true });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// ==================== VERSIONING ====================

app.post('/api/groups/:id/save-version', auth, async (req, res) => {
    try {
        const { versionName } = req.body;
        const groupId = req.params.id;
        
        // קבל גרסה נוכחית
        const g = await pool.query('SELECT version FROM contact_groups WHERE id = $1', [groupId]);
        const newVersion = (g.rows[0]?.version || 0) + 1;
        
        // קבל את כל אנשי הקשר
        const contacts = await pool.query('SELECT * FROM contacts WHERE group_id = $1', [groupId]);
        
        // שמור snapshot
        await pool.query(
            `INSERT INTO group_versions (group_id, version_number, version_name, contacts_snapshot, stats) 
             VALUES ($1, $2, $3, $4, (SELECT stats FROM contact_groups WHERE id = $1))`,
            [groupId, newVersion, versionName || `גרסה ${newVersion}`, JSON.stringify(contacts.rows)]
        );
        
        // עדכן מספר גרסה
        await pool.query('UPDATE contact_groups SET version = $2 WHERE id = $1', [groupId, newVersion]);
        
        res.json({ success: true, version: newVersion });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

app.post('/api/groups/:id/restore-version/:versionId', auth, async (req, res) => {
    try {
        const { id, versionId } = req.params;
        
        // קבל את ה-snapshot
        const v = await pool.query('SELECT * FROM group_versions WHERE id = $1 AND group_id = $2', [versionId, id]);
        if (!v.rows[0]) return res.status(404).json({ error: 'Version not found' });
        
        const snapshot = v.rows[0].contacts_snapshot;
        
        // מחק אנשי קשר קיימים
        await pool.query('DELETE FROM contacts WHERE group_id = $1', [id]);
        
        // שחזר מה-snapshot
        if (snapshot && snapshot.length > 0) {
            for (const c of snapshot) {
                await pool.query(
                    `INSERT INTO contacts (group_id, full_name, phone, phone_normalized, email, source_file_id, source_file_name, original_data, metadata) 
                     VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)`,
                    [id, c.full_name, c.phone, c.phone_normalized, c.email, c.source_file_id, c.source_file_name, 
                     JSON.stringify(c.original_data || {}), JSON.stringify(c.metadata || {})]
                );
            }
        }
        
        // עדכן סטטיסטיקות
        await pool.query('UPDATE contact_groups SET stats = $2 WHERE id = $1', [id, JSON.stringify(v.rows[0].stats || {})]);
        
        res.json({ success: true, restoredCount: snapshot?.length || 0 });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

app.get('/api/groups/:id/versions', auth, async (req, res) => {
    try {
        const versions = await pool.query(
            `SELECT id, version_number, version_name, 
                    jsonb_array_length(contacts_snapshot) as contacts_count,
                    stats,
                    to_char(created_at, 'DD/MM/YYYY HH24:MI') as created_at_formatted
             FROM group_versions WHERE group_id = $1 ORDER BY version_number DESC`,
            [req.params.id]
        );
        res.json(versions.rows);
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// ==================== ADD TO EXISTING GROUP ====================

app.post('/api/groups/:id/add-files', auth, async (req, res) => {
    const { processingData, defaultName } = req.body;
    const groupId = req.params.id;
    
    try {
        // שמור גרסה נוכחית לפני השינוי
        const g = await pool.query('SELECT * FROM contact_groups WHERE id = $1', [groupId]);
        if (!g.rows[0] || g.rows[0].status !== 'ready') {
            return res.status(400).json({ error: 'Group not ready for additions' });
        }
        
        const currentContacts = await pool.query('SELECT * FROM contacts WHERE group_id = $1', [groupId]);
        const newVersion = (g.rows[0].version || 0) + 1;
        
        // שמור snapshot
        await pool.query(
            `INSERT INTO group_versions (group_id, version_number, version_name, contacts_snapshot, stats) 
             VALUES ($1, $2, $3, $4, $5)`,
            [groupId, newVersion, `לפני הוספת קבצים`, JSON.stringify(currentContacts.rows), JSON.stringify(g.rows[0].stats)]
        );
        
        // בנה map של טלפונים קיימים
        const existingPhones = new Map();
        currentContacts.rows.forEach(c => existingPhones.set(c.phone_normalized || c.phone, c));
        
        let added = 0, skipped = 0, duplicates = 0;
        let serial = currentContacts.rows.length + 1;
        
        for (const item of processingData) {
            const fileRes = await pool.query('SELECT * FROM uploaded_files WHERE id = $1', [item.fileId]);
            if (!fileRes.rows[0]) continue;
            const file = fileRes.rows[0];
            
            let rows = [];
            if (file.file_path.toLowerCase().endsWith('.vcf')) {
                rows = parseVcf(fs.readFileSync(file.file_path, 'utf8'));
            } else {
                const stream = fs.createReadStream(file.file_path).pipe(csv());
                for await (const row of stream) rows.push(row);
            }
            
            for (const row of rows) {
                const rawPhone = row[item.mapping.phoneField];
                const phoneResult = normalizePhone(rawPhone);
                
                if (!phoneResult.normalized) {
                    skipped++;
                    continue;
                }
                
                const phone = phoneResult.normalized;
                
                if (existingPhones.has(phone)) {
                    duplicates++;
                    continue;
                }
                
                let name = cleanName(item.mapping.nameFields.map(f => row[f] || '').join(' '));
                if (!name) name = `${defaultName || 'איש קשר'} ${serial++}`;
                
                await pool.query(
                    `INSERT INTO contacts (group_id, full_name, phone, phone_normalized, email, source_file_id, source_file_name, original_data, metadata) 
                     VALUES ($1, $2, $3, $4, $5, $6, $7, $8, '{}')`,
                    [groupId, name, phone, phone, row.Email || '', file.id, file.original_name, JSON.stringify(row.OriginalData || {})]
                );
                
                existingPhones.set(phone, true);
                added++;
            }
            
            await pool.query("UPDATE uploaded_files SET status = 'processed' WHERE id = $1", [file.id]);
        }
        
        // עדכן גרסה
        await pool.query('UPDATE contact_groups SET version = $2 WHERE id = $1', [groupId, newVersion + 1]);
        
        res.json({ success: true, added, skipped, duplicates });
    } catch (err) {
        console.error('[ADD-FILES] Error:', err);
        res.status(500).json({ error: err.message });
    }
});

// ==================== EXPORT ====================

app.get('/api/export/:type/:id', auth, async (req, res) => {
    try {
        const r = await pool.query('SELECT full_name, phone, email FROM contacts WHERE group_id = $1', [req.params.id]);
        const g = await pool.query('SELECT name FROM contact_groups WHERE id = $1', [req.params.id]);
        const groupName = g.rows[0]?.name || 'contacts';
        
        let out = '';
        if (req.params.type === 'csv') {
            out = "Name,Phone,Email\n";
            r.rows.forEach(c => {
                out += `"${c.full_name}","${c.phone}","${c.email || ''}"\n`;
            });
        } else {
            r.rows.forEach(c => {
                out += `BEGIN:VCARD\nVERSION:3.0\nFN:${c.full_name}\nTEL;TYPE=CELL:${c.phone}\n`;
                if (c.email) out += `EMAIL:${c.email}\n`;
                out += `END:VCARD\n`;
            });
        }
        
        res.setHeader('Content-Type', req.params.type === 'csv' ? 'text/csv; charset=utf-8' : 'text/vcard; charset=utf-8');
        res.setHeader('Content-Disposition', `attachment; filename="${groupName}.${req.params.type}"`);
        res.send('\ufeff' + out); // BOM for Excel
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// ==================== CONTACT EDITING ====================

// עדכון שם איש קשר
app.put('/api/contacts/:id', auth, async (req, res) => {
    try {
        const { full_name } = req.body;
        if (!full_name || !full_name.trim()) {
            return res.status(400).json({ error: 'Name is required' });
        }
        
        await pool.query('UPDATE contacts SET full_name = $1 WHERE id = $2', [full_name.trim(), req.params.id]);
        res.json({ success: true });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// מציאת שמות כפולים בקבוצה
app.get('/api/groups/:id/duplicates', auth, async (req, res) => {
    try {
        const r = await pool.query(`
            SELECT full_name, array_agg(id) as ids, count(*) as count
            FROM contacts 
            WHERE group_id = $1
            GROUP BY full_name
            HAVING count(*) > 1
            ORDER BY count DESC, full_name
        `, [req.params.id]);
        
        res.json({
            duplicates: r.rows,
            totalDuplicateNames: r.rows.length,
            totalDuplicateContacts: r.rows.reduce((sum, d) => sum + parseInt(d.count), 0)
        });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// תיקון אוטומטי של שמות כפולים - הוספת מספרים
app.post('/api/groups/:id/fix-duplicates', auth, async (req, res) => {
    try {
        const groupId = req.params.id;
        
        // שמור גרסה לפני השינוי
        const g = await pool.query('SELECT * FROM contact_groups WHERE id = $1', [groupId]);
        const currentContacts = await pool.query('SELECT * FROM contacts WHERE group_id = $1', [groupId]);
        const newVersion = (g.rows[0]?.version || 0) + 1;
        
        await pool.query(
            `INSERT INTO group_versions (group_id, version_number, version_name, contacts_snapshot, stats) 
             VALUES ($1, $2, $3, $4, $5)`,
            [groupId, newVersion, 'לפני תיקון כפילויות', JSON.stringify(currentContacts.rows), JSON.stringify(g.rows[0]?.stats)]
        );
        
        // מצא כפילויות
        const dupsRes = await pool.query(`
            SELECT full_name, array_agg(id ORDER BY id) as ids
            FROM contacts 
            WHERE group_id = $1
            GROUP BY full_name
            HAVING count(*) > 1
        `, [groupId]);
        
        let fixed = 0;
        for (const dup of dupsRes.rows) {
            const ids = dup.ids;
            // השאר את הראשון כמו שהוא, הוסף מספרים לשאר
            for (let i = 1; i < ids.length; i++) {
                const newName = `${dup.full_name} (${i + 1})`;
                await pool.query('UPDATE contacts SET full_name = $1 WHERE id = $2', [newName, ids[i]]);
                fixed++;
            }
        }
        
        await pool.query('UPDATE contact_groups SET version = $2 WHERE id = $1', [groupId, newVersion + 1]);
        
        res.json({ success: true, fixed, duplicateGroups: dupsRes.rows.length });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// ==================== STATS & DASHBOARD ====================

app.get('/api/dashboard-stats', auth, async (req, res) => {
    try {
        const groups = await pool.query("SELECT count(*) as total, count(*) FILTER (WHERE status = 'ready') as ready, count(*) FILTER (WHERE status = 'draft') as draft FROM contact_groups");
        const contacts = await pool.query("SELECT count(*) as total FROM contacts");
        const files = await pool.query("SELECT count(*) as total, count(*) FILTER (WHERE status = 'pending') as pending FROM uploaded_files");
        
        res.json({
            groups: groups.rows[0],
            contacts: contacts.rows[0],
            files: files.rows[0]
        });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// ==================== SETTINGS & INVALID NAMES ====================

// רשימת שמות לא תקינים
app.get('/api/invalid-names', auth, async (req, res) => {
    try {
        const r = await pool.query('SELECT * FROM invalid_names ORDER BY name');
        res.json(r.rows);
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

app.post('/api/invalid-names', auth, async (req, res) => {
    try {
        const { name, patternType = 'exact' } = req.body;
        await pool.query(
            'INSERT INTO invalid_names (name, pattern_type) VALUES ($1, $2) ON CONFLICT DO NOTHING',
            [name, patternType]
        );
        invalidNamesCache = null; // אפס את הקאש
        res.json({ success: true });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

app.delete('/api/invalid-names/:id', auth, async (req, res) => {
    try {
        await pool.query('DELETE FROM invalid_names WHERE id = $1', [req.params.id]);
        invalidNamesCache = null;
        res.json({ success: true });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// כללי בחירת שמות
app.get('/api/settings/name-rules', auth, async (req, res) => {
    try {
        const r = await pool.query("SELECT value FROM system_settings WHERE key = 'name_rules'");
        res.json(r.rows[0]?.value || {});
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

app.put('/api/settings/name-rules', auth, async (req, res) => {
    try {
        await pool.query(
            `INSERT INTO system_settings (key, value, updated_at) VALUES ('name_rules', $1, CURRENT_TIMESTAMP)
             ON CONFLICT (key) DO UPDATE SET value = $1, updated_at = CURRENT_TIMESTAMP`,
            [JSON.stringify(req.body)]
        );
        nameRulesCache = null; // אפס קאש
        res.json({ success: true });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// ==================== HEALTH & TEST ====================

app.get('/api/health', (req, res) => {
    res.json({ status: 'ok', timestamp: new Date().toISOString() });
});

app.get('/api/test-parse/:fileId', auth, async (req, res) => {
    try {
        const fileRes = await pool.query('SELECT * FROM uploaded_files WHERE id = $1', [req.params.fileId]);
        if (!fileRes.rows[0]) return res.status(404).json({ error: 'File not found' });
        
        const file = fileRes.rows[0];
        const content = fs.readFileSync(file.file_path, 'utf8');
        const actualVcards = (content.match(/BEGIN:VCARD/gi) || []).length;
        
        const parsed = parseVcf(content);
        let validPhones = 0, rejectedPhones = 0;
        const rejectionReasons = {};
        const rejectedSamples = [];
        
        parsed.forEach(c => {
            const result = normalizePhone(c.Phone);
            if (result.normalized) {
                validPhones++;
            } else {
                rejectedPhones++;
                rejectionReasons[result.reason] = (rejectionReasons[result.reason] || 0) + 1;
                if (rejectedSamples.length < 20) rejectedSamples.push(c);
            }
        });
        
        // מצא את כל שמות השדות ב-VCF
        const fieldNames = new Set();
        const unfoldedContent = content.replace(/\r\n/g, '\n').replace(/\r/g, '\n').replace(/\n[ \t]/g, '');
        unfoldedContent.split('\n').forEach(line => {
            const match = line.match(/^([A-Z][A-Z0-9\-]*)/i);
            if (match && !['BEGIN', 'END', 'VERSION'].includes(match[1].toUpperCase())) {
                fieldNames.add(match[1].toUpperCase().split(';')[0]);
            }
        });
        
        res.json({
            fileName: file.original_name,
            fileSize: content.length,
            actualVcards,
            parsedContacts: parsed.length,
            validPhones,
            rejectedPhones,
            rejectionReasons,
            fieldNames: [...fieldNames],
            sample: parsed.slice(0, 10),
            rejectedSamples
        });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// ==================== START SERVER ====================

app.listen(3377, () => {
    console.log('[VCF Server] Running on port 3377');
    console.log('[VCF Server] Database:', process.env.DB_HOST || '127.0.0.1', ':', process.env.DB_PORT || 3378);
});
