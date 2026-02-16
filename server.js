const express = require('express');
const multer = require('multer');
const { Pool } = require('pg');
const fs = require('fs');
const path = require('path');
const session = require('express-session');
const pgSession = require('connect-pg-simple')(session);
const passport = require('passport');
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const csv = require('csv-parser');
const crypto = require('crypto');

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

// Session store בדאטאבייס - שורד רענון ורסטארט
app.use(express.json({limit: '350mb'}));
app.use(express.static(__dirname));
app.use(session({ 
    store: new pgSession({
        pool: pool,
        tableName: 'user_sessions',
        createTableIfMissing: true
    }),
    secret: 'vcf-luxury-elite-v8-final-2024', 
    resave: false, 
    saveUninitialized: false, 
    cookie: { 
        maxAge: 30 * 24 * 60 * 60 * 1000, // 30 ימים
        secure: false, // שנה ל-true אם יש HTTPS
        httpOnly: true,
        sameSite: 'lax'
    } 
}));

// Passport setup
app.use(passport.initialize());
app.use(passport.session());

// רשימת מיילים מורשים
const ALLOWED_EMAILS = [
    'office@neriyabudraham.co.il',
    'neriyabudraham@gmail.com'
];

// Google OAuth Strategy - מוגדר רק אם יש credentials
const GOOGLE_CLIENT_ID = process.env.GOOGLE_CLIENT_ID;
const GOOGLE_CLIENT_SECRET = process.env.GOOGLE_CLIENT_SECRET;
const GOOGLE_CALLBACK_URL = process.env.GOOGLE_CALLBACK_URL || 'https://vcf.botomat.co.il/auth/google/callback';

if (GOOGLE_CLIENT_ID && GOOGLE_CLIENT_SECRET) {
    passport.use(new GoogleStrategy({
        clientID: GOOGLE_CLIENT_ID,
        clientSecret: GOOGLE_CLIENT_SECRET,
        callbackURL: GOOGLE_CALLBACK_URL
    }, (accessToken, refreshToken, profile, done) => {
        const email = profile.emails?.[0]?.value;
        if (email && ALLOWED_EMAILS.includes(email.toLowerCase())) {
            return done(null, { email, name: profile.displayName, picture: profile.photos?.[0]?.value });
        }
        return done(null, false, { message: 'Email not authorized' });
    }));
    console.log('[AUTH] Google OAuth enabled with callback:', GOOGLE_CALLBACK_URL);
} else {
    console.log('[AUTH] Google OAuth disabled - set GOOGLE_CLIENT_ID and GOOGLE_CLIENT_SECRET env vars');
}

passport.serializeUser((user, done) => done(null, user));
passport.deserializeUser((user, done) => done(null, user));

const auth = (req, res, next) => {
    if (req.session && req.session.authenticated) return next();
    if (req.isAuthenticated && req.isAuthenticated()) {
        req.session.authenticated = true;
        return next();
    }
    if (req.path.startsWith('/api')) return res.status(401).json({ error: 'Session Expired' });
    res.redirect('/login');
};

// ==================== UTILITY FUNCTIONS ====================

const normalizePhone = (p, options = {}) => {
    const { allowShort = false, minLength = 7 } = options;
    
    if(!p) return { normalized: null, reason: 'empty_phone' };
    let c = p.toString().replace(/\D/g, '');
    if(!c || c.length === 0) return { normalized: null, reason: 'empty_phone' };
    
    // אם מאפשרים מספרים קצרים, המינימום הוא 1; אחרת לפי ההגדרה
    const effectiveMinLength = allowShort ? 1 : minLength;
    if(c.length < effectiveMinLength) return { normalized: null, reason: 'too_short', original: c };
    if(c.length > 15) return { normalized: null, reason: 'too_long', original: c };
    
    // נרמול מספרים ישראליים (רק למספרים ארוכים)
    if(c.length >= 9) {
        if(c.startsWith('05')) c = '972' + c.substring(1);
        else if(c.startsWith('5') && c.length === 9) c = '972' + c;
        else if(c.startsWith('00972')) c = '972' + c.substring(5);
        // אם מתחיל ב-972, כבר מנורמל
    }
    
    return { normalized: c, reason: null };
};

const getBaseName = (name) => {
    if (!name) return '';
    // הסר (X) מהסוף
    let base = name.toString().replace(/\s?\(\d+\)$/g, '').trim();
    // הסר מספרים מהסוף (כמו "דוד 13" -> "דוד")
    base = base.replace(/\s+\d+$/g, '').trim();
    return base;
};

// בדיקה אם שם הוא אותו שם בסיסי (דוד = דוד 13 = דוד (2))
const isSameBaseName = (name1, name2) => {
    if (!name1 || !name2) return false;
    return getBaseName(name1).toLowerCase() === getBaseName(name2).toLowerCase();
};

// בדיקה אם שם מכיל מספר בסוף
const hasNumberSuffix = (name) => {
    if (!name) return false;
    return /\s+\d+$/.test(name.toString().trim()) || /\s*\(\d+\)$/.test(name.toString().trim());
};

// בדיקה אם שם הוא שם דיפולטיבי (איש קשר XXX, צופה XXX וכו')
const isDefaultName = (name) => {
    if (!name) return false;
    const s = name.toString().trim();
    // שם שמתחיל עם מילה ואחריה מספר
    return /^(איש קשר|צופה|contact|משתמש|לקוח|user|client)\s+\d+$/i.test(s) ||
           /^(איש קשר|צופה|contact|משתמש|לקוח|user|client)\s+\d+\s*\(\d+\)$/i.test(s);
};

// חילוץ המספר מתוך שם דיפולטיבי
const getDefaultNameNumber = (name) => {
    if (!name) return Infinity;
    const match = name.toString().match(/(\d+)(?:\s*\(\d+\))?$/);
    return match ? parseInt(match[1]) : Infinity;
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

// ספירת תווים "אמיתיים" בשם (אותיות בלבד, בלי סימנים/אימוג'ים)
function countRealChars(name) {
    if (!name) return 0;
    // רק אותיות עברית, אנגלית ורווחים
    const realChars = name.match(/[א-תa-zA-Z\s]/g) || [];
    // הסר רווחים מהספירה
    return realChars.filter(c => c !== ' ').length;
}

// בדיקה אם שם קצר מדי
async function isNameTooShort(name) {
    const rules = nameRulesCache || await loadNameRules();
    const minLength = rules.minLength ?? 2; // ברירת מחדל: 2 תווים
    if (minLength <= 0) return false;
    return countRealChars(name) < minLength;
}

// חישוב ציון לשם (ככל שגבוה יותר - השם טוב יותר)
async function scoreName(name) {
    if (!name || name.trim() === '') return -1000;
    if (await isInvalidName(name)) return -1000;
    if (await isNameTooShort(name)) return -1000; // שם קצר מדי
    
    const rules = nameRulesCache || await loadNameRules();
    let score = 0;
    const n = name.trim();
    const realLength = countRealChars(n);
    
    // אורך - עדיפות לארוך יותר אבל לא יותר מדי
    if (rules.preferLonger) {
        if (realLength <= (rules.maxLength || 20)) {
            score += realLength * 2;
        } else {
            score -= (realLength - rules.maxLength) * 3; // קנס על שם ארוך מדי
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

// כללי ניקוי שמות
let cleaningRulesCache = null;

async function loadCleaningRules() {
    try {
        const res = await pool.query("SELECT value FROM system_settings WHERE key = 'cleaning_rules'");
        cleaningRulesCache = res.rows[0]?.value || getDefaultCleaningRules();
    } catch (e) {
        cleaningRulesCache = getDefaultCleaningRules();
    }
    return cleaningRulesCache;
}

function getDefaultCleaningRules() {
    return [
        { id: 1, type: 'trim_start', pattern: '.', description: 'הסר נקודה מתחילת השם', enabled: true },
        { id: 2, type: 'trim_start', pattern: ' ', description: 'הסר רווח מתחילת השם', enabled: true },
        { id: 3, type: 'trim_end', pattern: '.', description: 'הסר נקודה מסוף השם', enabled: true },
        { id: 4, type: 'trim_end', pattern: ' ', description: 'הסר רווח מסוף השם', enabled: true },
        { id: 5, type: 'replace', pattern: '  ', replacement: ' ', description: 'הסר רווחים כפולים', enabled: true },
        { id: 6, type: 'trim_start', pattern: '-', description: 'הסר מקף מתחילת השם', enabled: true },
        { id: 7, type: 'trim_start', pattern: '_', description: 'הסר קו תחתון מתחילת השם', enabled: true },
    ];
}

// ניקוי שם לפי הכללים
async function cleanName(name) {
    if (!name) return name;
    
    // Force reload of rules each time to ensure fresh data
    await loadCleaningRules();
    const rules = cleaningRulesCache || [];
    let cleaned = name;
    
    // עבור על כל כלל עד שאין שינוי
    let changed = true;
    let iterations = 0;
    while (changed && iterations < 10) {
        changed = false;
        iterations++;
        
        for (const rule of rules) {
            if (!rule.enabled) continue;
            
            const before = cleaned;
            
            switch (rule.type) {
                case 'trim_start':
                    while (cleaned.startsWith(rule.pattern)) {
                        cleaned = cleaned.slice(rule.pattern.length);
                    }
                    break;
                    
                case 'trim_end':
                    while (cleaned.endsWith(rule.pattern)) {
                        cleaned = cleaned.slice(0, -rule.pattern.length);
                    }
                    break;
                    
                case 'replace':
                    // For literal replacement, use split+join
                    cleaned = cleaned.split(rule.pattern).join(rule.replacement ?? '');
                    break;
                    
                case 'regex':
                    try {
                        const regex = new RegExp(rule.pattern, 'g');
                        cleaned = cleaned.replace(regex, rule.replacement ?? '');
                    } catch (e) {
                        console.log('[CLEAN] Regex error for pattern:', rule.pattern, e.message);
                    }
                    break;
                    
                case 'remove_special':
                    // הסר את כל התווים והאימוג'ים למעט אותיות ורווחים ותווים מותרים
                    const allowedChars = rule.pattern || '';
                    // בנה regex שישמור רק על: אותיות עברית, אותיות אנגלית, מספרים, רווחים, ותווים מותרים
                    // תווים שצריכים בריחה ב-regex character class
                    const escapeForCharClass = (char) => {
                        const needsEscape = ['^', '-', '\\', ']', '['];
                        return needsEscape.includes(char) ? '\\' + char : char;
                    };
                    let allowedPattern = 'א-תa-zA-Z0-9\\s';
                    // הוסף תווים מותרים נוספים
                    for (const char of allowedChars) {
                        allowedPattern += escapeForCharClass(char);
                    }
                    try {
                        const removeRegex = new RegExp(`[^${allowedPattern}]`, 'gu');
                        cleaned = cleaned.replace(removeRegex, '');
                    } catch (e) {
                        console.log('[CLEAN] Remove special error:', e.message);
                    }
                    break;
            }
            
            if (before !== cleaned) {
                changed = true;
            }
        }
    }
    
    const result = cleaned.trim();
    
    // אם התוצאה היא רק מספר בסוגריים - החזר ריק
    if (/^\s*\(\d+\)\s*$/.test(result)) return '';
    
    // אם השם קצר מדי - החזר ריק
    const nameRules = nameRulesCache || await loadNameRules();
    const minLength = nameRules.minLength ?? 2; // ברירת מחדל: 2 תווים
    if (minLength > 0 && countRealChars(result) < minLength) return '';
    
    return result;
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

// יצירת שם ייחודי עם סיומת מספור
async function makeUniqueName(name, existingNames, phone = '') {
    if (!name) return name;
    let baseName = getBaseName(name);
    
    // אם השם ריק או רק מספרים בסוגריים - תן שם דיפולטיבי
    if (!baseName || /^\s*\(\d+\)\s*$/.test(baseName)) {
        baseName = `איש קשר ${phone ? phone.slice(-4) : Math.random().toString().slice(2, 6)}`;
    }
    
    if (!existingNames.has(baseName.toLowerCase())) {
        existingNames.add(baseName.toLowerCase());
        return baseName;
    }
    
    // קבל את פורמט הסיומת מההגדרות
    const rules = await loadNameRules();
    const suffixFormat = rules.duplicateSuffix || '({n})'; // ברירת מחדל: (1), (2), (3)...
    
    let counter = 1;
    let uniqueName;
    do {
        uniqueName = `${baseName} ${suffixFormat.replace('{n}', counter)}`;
        counter++;
    } while (existingNames.has(uniqueName.toLowerCase()));
    
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
        let name = '';
        let email = '';
        let phones = []; // { number, type }
        let originalData = {};

        for (const line of lines) {
            const trimmed = line.trim();
            if (!trimmed) continue;
            const upper = trimmed.toUpperCase();
            const colonIdx = trimmed.indexOf(':');
            const valueRaw = colonIdx > -1 ? trimmed.substring(colonIdx + 1).trim() : '';
            const value = decodeVcfValue(valueRaw, upper);
            
            // שם - בדוק כל האפשרויות
            if (upper.startsWith('FN:') || upper.startsWith('FN;')) {
                if (value) name = value;
            }
            else if ((upper.startsWith('N:') || upper.startsWith('N;')) && !upper.startsWith('NOTE') && !upper.startsWith('NICKNAME')) {
                const nameParts = value.split(';').filter(part => part.trim()).join(' ');
                if (nameParts && !name) name = nameParts;
            }
            else if (upper.startsWith('NICKNAME:') || upper.startsWith('NICKNAME;')) {
                if (value && !name) name = value;
            }
            // טלפון - חיפוש מקיף בכל הפורמטים האפשריים
            else if (
                upper.startsWith('TEL:') || upper.startsWith('TEL;') || 
                upper.match(/^ITEM\d*\.TEL/) || 
                upper.startsWith('X-TEL') || upper.startsWith('X-PHONE') ||
                upper.includes('.TEL:') || upper.includes('.TEL;') ||
                upper.startsWith('PHONE:') || upper.startsWith('PHONE;') ||
                upper.startsWith('X-MOBILE') || upper.startsWith('X-CELL') ||
                upper.startsWith('X-MAIN-PHONE') || upper.startsWith('X-OTHER-PHONE') ||
                upper.startsWith('X-WORK-PHONE') || upper.startsWith('X-HOME-PHONE') ||
                upper.match(/^X-.*PHONE/) || upper.match(/^X-.*TEL/)
            ) {
                // חלץ את מספר הטלפון
                let phoneVal = trimmed.substring(trimmed.lastIndexOf(':') + 1);
                phoneVal = phoneVal.replace(/[^\d+\-\s\(\)]/g, '').replace(/[\s\-\(\)]/g, '');
                
                // קבע את סוג הטלפון
                let phoneType = 'טלפון';
                if (upper.includes('CELL') || upper.includes('MOBILE')) phoneType = 'נייד';
                else if (upper.includes('WORK')) phoneType = 'עבודה';
                else if (upper.includes('HOME')) phoneType = 'בית';
                else if (upper.includes('FAX')) phoneType = 'פקס';
                else if (upper.includes('PAGER')) phoneType = 'איתורית';
                else if (upper.includes('MAIN')) phoneType = 'ראשי';
                else if (upper.includes('OTHER')) phoneType = 'אחר';
                
                if (phoneVal && phoneVal.length >= 4) {
                    // בדוק שאין כפילות
                    if (!phones.find(p => p.number === phoneVal)) {
                        phones.push({ number: phoneVal, type: phoneType });
                    }
                }
            }
            // אימייל
            else if (upper.startsWith('EMAIL:') || upper.startsWith('EMAIL;')) {
                if (value && !email) email = value;
            }
            // נתונים נוספים
            else if (upper.startsWith('ORG:') || upper.startsWith('ORG;')) {
                originalData.organization = value;
                // אם אין שם, נסה לקחת מהארגון
                if (!name && value) name = value;
            }
            else if (upper.startsWith('NOTE:') || upper.startsWith('NOTE;')) {
                originalData.note = value;
                // חפש מספרי טלפון גם בהערות
                const phoneMatches = value.match(/(\+?972[\d\-\s]{8,}|05\d[\d\-\s]{7,}|\d{9,})/g);
                if (phoneMatches) {
                    phoneMatches.forEach(pm => {
                        const cleanPhone = pm.replace(/[\s\-]/g, '');
                        if (cleanPhone.length >= 9 && !phones.find(p => p.number === cleanPhone)) {
                            phones.push({ number: cleanPhone, type: 'מהערה' });
                        }
                    });
                }
            }
            // חפש גם בשדות מותאמים אישית
            else if (upper.startsWith('X-') && value) {
                // שדות מותאמים שעשויים להכיל טלפון
                const phoneMatch = value.match(/^(\+?[\d\-\s\(\)]{7,})$/);
                if (phoneMatch) {
                    const cleanPhone = phoneMatch[1].replace(/[\s\-\(\)]/g, '');
                    if (cleanPhone.length >= 7 && !phones.find(p => p.number === cleanPhone)) {
                        phones.push({ number: cleanPhone, type: 'שדה מותאם' });
                    }
                }
            }
        }
        
        // שמור את כל הטלפונים המקוריים
        originalData.allPhones = phones.map(p => ({ ...p }));
        
        // צור איש קשר נפרד לכל מספר טלפון
        if (phones.length > 0) {
            phones.forEach((phoneObj, idx) => {
                contacts.push({
                    Name: name || '',
                    Phone: phoneObj.number,
                    PhoneType: phoneObj.type,
                    Email: email,
                    OriginalData: { 
                        ...originalData,
                        phoneIndex: idx,
                        totalPhones: phones.length
                    }
                });
            });
        } else if (name) {
            // אין טלפון אבל יש שם - שמור בכל זאת (יידחה אח"כ עם סיבה)
            contacts.push({
                Name: name,
                Phone: '',
                Email: email,
                OriginalData: originalData
            });
        }
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

app.get('/login', (req, res) => {
    // אם כבר מחובר, הפנה לדף הבית
    if (req.session?.authenticated || (req.isAuthenticated && req.isAuthenticated())) {
        return res.redirect('/');
    }
    res.sendFile(path.join(__dirname, 'login.html'));
});

// התחברות רגילה עם מייל
app.post('/login', (req, res) => {
    const email = req.body.email?.toLowerCase();
    if (email && ALLOWED_EMAILS.includes(email)) { 
        req.session.authenticated = true;
        req.session.user = { email };
        return res.json({ success: true }); 
    }
    res.status(401).json({ error: 'Email not authorized' });
});

// Google OAuth - התחלת התהליך
app.get('/auth/google', passport.authenticate('google', { 
    scope: ['profile', 'email'] 
}));

// Google OAuth - callback
app.get('/auth/google/callback', 
    passport.authenticate('google', { failureRedirect: '/login?error=unauthorized' }),
    (req, res) => {
        req.session.authenticated = true;
        req.session.user = req.user;
        res.redirect('/');
    }
);

// יציאה מהמערכת
app.get('/logout', (req, res) => {
    req.session.destroy((err) => {
        if (req.logout) {
            req.logout(() => {});
        }
        res.redirect('/login');
    });
});

// קבלת מידע על המשתמש המחובר
app.get('/api/me', auth, (req, res) => {
    res.json({
        authenticated: true,
        user: req.session.user || req.user || { email: 'unknown' }
    });
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
        const fileId = req.params.id;
        console.log(`[DELETE FILE] Deleting file ${fileId}`);
        
        // נתק הפניות מאנשי קשר
        await pool.query('UPDATE contacts SET source_file_id = NULL WHERE source_file_id = $1', [fileId]);
        
        // מחק את הקובץ
        const fRes = await pool.query('DELETE FROM uploaded_files WHERE id = $1 RETURNING file_path', [fileId]);
        
        // מחק את הקובץ מהדיסק
        if (fRes.rows[0]?.file_path && fs.existsSync(fRes.rows[0].file_path)) {
            try { fs.unlinkSync(fRes.rows[0].file_path); } catch (e) { /* ignore */ }
        }
        
        console.log(`[DELETE FILE] File ${fileId} deleted successfully`);
        res.json({ success: true });
    } catch (err) {
        console.error('[DELETE FILE] Error:', err);
        res.status(500).json({ error: err.message });
    }
});

// ==================== ANALYZE & PROCESS ====================

app.post('/api/analyze', auth, async (req, res) => {
    const { processingData, defaultName, startSerial, groupId, targetGroupName, addToGroupId, allowShortPhones } = req.body;
    const phoneOptions = { allowShort: allowShortPhones || false };
    
    try {
        let responseData;

        if (groupId) {
            // טעינת טיוטה קיימת - החל כללי ניקוי מעודכנים
            const g = await pool.query('SELECT draft_data, name FROM contact_groups WHERE id = $1', [groupId]);
            if (!g.rows[0]) return res.status(404).json({ error: 'Group not found' });
            responseData = g.rows[0].draft_data;
            responseData.targetGroupName = g.rows[0].name;
            
            // רענן קאש של כללים
            nameRulesCache = null;
            cleaningRulesCache = null;
            invalidNamesCache = null;
            await loadNameRules();
            await loadCleaningRules();
            await loadInvalidNames();
            
            // החל כללי ניקוי על כל השמות
            let serial = 1;
            const phoneMap = new Map();
            const newConflicts = [];
            
            console.log(`[ANALYZE] Re-applying rules to ${responseData.allData?.length || 0} contacts`);
            
            // עדכן את allData עם שמות מנוקים
            for (const contact of responseData.allData || []) {
                let cleanedName = await cleanName(contact.name);
                
                // אם השם ריק אחרי הניקוי - תן שם דיפולטיבי
                if (!cleanedName || !cleanedName.trim() || /^\s*\(\d+\)\s*$/.test(cleanedName)) {
                    cleanedName = `איש קשר ${contact.phone?.slice(-4) || serial++}`;
                }
                
                // בדוק אם השם ברשימה השחורה
                if (await isInvalidName(cleanedName)) {
                    cleanedName = `איש קשר ${contact.phone?.slice(-4) || serial++}`;
                }
                
                // בדוק אם השם קצר מדי
                if (await isNameTooShort(cleanedName)) {
                    cleanedName = `איש קשר ${contact.phone?.slice(-4) || serial++}`;
                }
                
                contact.name = cleanedName;
                phoneMap.set(contact.phone, contact);
            }
            
            // עדכן קונפליקטים עם שמות מנוקים + חשב ניקוד מחדש
            for (const conflict of responseData.conflicts || []) {
                const cleanedNames = [];
                const newScores = [];
                const sources = [];
                
                for (let i = 0; i < conflict.names.length; i++) {
                    let cleanedName = await cleanName(conflict.names[i]);
                    if (!cleanedName || !cleanedName.trim() || /^\s*\(\d+\)\s*$/.test(cleanedName) || 
                        await isInvalidName(cleanedName) || await isNameTooShort(cleanedName)) {
                        cleanedName = `איש קשר ${conflict.phone?.slice(-4) || ''}`;
                    }
                    cleanedNames.push(cleanedName);
                    newScores.push(await scoreName(cleanedName));
                    sources.push(conflict.sources?.[i] || '');
                }
                
                // סנן שמות דיפולטיביים אם יש שמות אמיתיים
                const realNames = cleanedNames.filter(n => !isDefaultName(n));
                
                let filteredNames, filteredScores, filteredSources;
                if (realNames.length > 0) {
                    // יש שמות אמיתיים - השאר רק אותם
                    filteredNames = [];
                    filteredScores = [];
                    filteredSources = [];
                    for (let i = 0; i < cleanedNames.length; i++) {
                        if (!isDefaultName(cleanedNames[i]) && !filteredNames.includes(cleanedNames[i])) {
                            filteredNames.push(cleanedNames[i]);
                            filteredScores.push(newScores[i]);
                            filteredSources.push(sources[i]);
                        }
                    }
                } else {
                    // כל השמות דיפולטיביים - בחר את המספר הנמוך ביותר
                    let lowestNum = Infinity;
                    let lowestIdx = 0;
                    for (let i = 0; i < cleanedNames.length; i++) {
                        const num = getDefaultNameNumber(cleanedNames[i]);
                        if (num < lowestNum) {
                            lowestNum = num;
                            lowestIdx = i;
                        }
                    }
                    filteredNames = [cleanedNames[lowestIdx]];
                    filteredScores = [newScores[lowestIdx]];
                    filteredSources = [sources[lowestIdx]];
                }
                
                // הסר שמות כפולים ושמות עם אותו בסיס (דוד, דוד 13 -> דוד)
                const uniqueNames = [];
                const uniqueScores = [];
                const uniqueSources = [];
                const usedBases = new Set();
                
                // מיין לפי עדיפות: שם בלי מספר קודם
                const sortedIndices = filteredNames.map((n, i) => i).sort((a, b) => {
                    const aHasNum = hasNumberSuffix(filteredNames[a]);
                    const bHasNum = hasNumberSuffix(filteredNames[b]);
                    if (!aHasNum && bHasNum) return -1;
                    if (aHasNum && !bHasNum) return 1;
                    return filteredScores[b] - filteredScores[a]; // מיין לפי ניקוד
                });
                
                for (const i of sortedIndices) {
                    const base = getBaseName(filteredNames[i]).toLowerCase();
                    // אם כבר יש שם עם אותו בסיס - דלג
                    if (usedBases.has(base)) continue;
                    
                    usedBases.add(base);
                    uniqueNames.push(filteredNames[i]);
                    uniqueScores.push(filteredScores[i]);
                    uniqueSources.push(filteredSources[i]);
                }
                
                conflict.names = uniqueNames;
                conflict.scores = uniqueScores;
                conflict.sources = uniqueSources;
                
                // בחר את השם הטוב ביותר (עדיפות לשם בלי מספר)
                let bestIdx = 0;
                for (let i = 0; i < uniqueNames.length; i++) {
                    if (!hasNumberSuffix(uniqueNames[i])) {
                        bestIdx = i;
                        break;
                    }
                }
                // אם כולם עם מספרים - בחר לפי ניקוד
                if (hasNumberSuffix(uniqueNames[bestIdx])) {
                    bestIdx = uniqueScores.indexOf(Math.max(...uniqueScores));
                }
                conflict.autoSelected = uniqueNames[bestIdx];
                
                // עדכן גם ב-allData
                const contact = phoneMap.get(conflict.phone);
                if (contact) contact.name = conflict.autoSelected;
            }
            
            // הסר קונפליקטים עם שם אחד בלבד (אחרי סינון שמות דיפולטיביים)
            responseData.conflicts = (responseData.conflicts || []).filter(c => c.names.length > 1);
            
            // מיין לפי אורך טלפון - מספרים ארוכים קודם (כך שמספרים קצרים יקבלו סיומת)
            const sortedData = (responseData.allData || []).sort((a, b) => {
                const aLen = (a.phone || '').length;
                const bLen = (b.phone || '').length;
                // מספרים ארוכים (תקינים) קודם
                return bLen - aLen;
            });
            
            // וודא שמות ייחודיים
            const usedNames = new Set();
            for (const contact of sortedData) {
                contact.name = await makeUniqueName(contact.name, usedNames, contact.phone);
            }
            responseData.allData = sortedData;
            
            console.log('[ANALYZE] Re-applied cleaning rules to draft');
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
                    const phoneResult = normalizePhone(rawPhone, phoneOptions);
                    
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
                    let name = await cleanName(item.mapping.nameFields.map(f => row[f] || '').join(' '));
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
                        
                        const existingIsDefault = isDefaultName(existing.name);
                        const newIsDefault = isDefaultName(name);
                        
                        // אם שניהם שמות דיפולטיביים - השאר את זה עם המספר הנמוך
                        if (existingIsDefault && newIsDefault) {
                            const existingNum = getDefaultNameNumber(existing.name);
                            const newNum = getDefaultNameNumber(name);
                            if (newNum < existingNum) {
                                existing.name = name;
                            }
                            // לא יוצרים קונפליקט בין שמות דיפולטיביים
                            continue;
                        }
                        
                        // אם רק החדש דיפולטיבי - התעלם ממנו
                        if (newIsDefault && !existingIsDefault) {
                            continue;
                        }
                        
                        // אם רק הקיים דיפולטיבי - החלף בחדש
                        if (existingIsDefault && !newIsDefault) {
                            existing.name = name;
                            continue;
                        }
                        
                        // שניהם שמות אמיתיים - בדוק אם יש להם אותו שם בסיסי
                        if (isSameBaseName(existing.name, name)) {
                            // שמות עם אותו בסיס (דוד = דוד 13) - בחר את זה בלי המספר
                            let bestName;
                            const existingHasNum = hasNumberSuffix(existing.name);
                            const newHasNum = hasNumberSuffix(name);
                            
                            if (!existingHasNum && newHasNum) {
                                // הקיים בלי מספר - עדיף
                                bestName = existing.name;
                            } else if (existingHasNum && !newHasNum) {
                                // החדש בלי מספר - עדיף
                                bestName = name;
                            } else {
                                // שניהם עם או בלי מספר - בחר לפי ניקוד
                                const existingScore = await scoreName(existing.name);
                                const newScore = await scoreName(name);
                                bestName = newScore > existingScore ? name : existing.name;
                            }
                            
                            existing.name = bestName;
                            if (!autoResolved.find(a => a.phone === phone)) {
                                autoResolved.push({ phone, name: bestName, allNames: [existing.name, name], count: 2 });
                            } else {
                                const ar = autoResolved.find(a => a.phone === phone);
                                ar.count++;
                                if (!ar.allNames.includes(name)) ar.allNames.push(name);
                            }
                        } else if (existing.name !== name) {
                            // שמות שונים - קונפליקט
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

            // מיין לפי אורך טלפון - מספרים ארוכים קודם
            const allData = Array.from(phoneMap.values()).sort((a, b) => {
                const aLen = (a.phone || '').length;
                const bLen = (b.phone || '').length;
                return bLen - aLen;
            });
            
            // וודא שמות ייחודיים
            const usedNames = new Set();
            for (const contact of allData) {
                contact.name = await makeUniqueName(contact.name, usedNames, contact.phone);
            }

            responseData = { 
                conflicts, 
                autoResolved, 
                rejectedContacts,
                allData,
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

// שמירת שינויים בטיוטה
app.post('/api/draft/:id/save', auth, async (req, res) => {
    try {
        const { allData, conflicts, autoResolved, rejectedContacts, stats } = req.body;
        
        const draftData = {
            allData: allData || [],
            conflicts: conflicts || [],
            autoResolved: autoResolved || [],
            rejectedContacts: rejectedContacts || [],
            stats: stats || {}
        };
        
        await pool.query(
            'UPDATE contact_groups SET draft_data = $1, updated_at = CURRENT_TIMESTAMP WHERE id = $2 AND status = $3',
            [JSON.stringify(draftData), req.params.id, 'draft']
        );
        
        res.json({ success: true });
    } catch (err) {
        console.error('[DRAFT SAVE] Error:', err);
        res.status(500).json({ error: err.message });
    }
});

// ==================== FINALIZE GROUP ====================

app.post('/api/finalize', auth, async (req, res) => {
    const { groupId, groupName, contacts, fileIds, stats, analysisData } = req.body;
    
    console.log(`[FINALIZE] Starting: groupId=${groupId}, contacts=${contacts?.length}, groupName=${groupName}`);
    
    try {
        const resolutions = await pool.query('SELECT phone, resolved_name FROM import_resolutions');
        const resMap = new Map(resolutions.rows.map(r => [r.phone, r.resolved_name]));

        const finalContacts = [];
        const usedNames = new Set();

        for (const c of contacts) {
            let name = resMap.get(c.phone) || c.name;
            
            // בדיקה אם השם לא תקין או ריק - החלף בשם ברירת מחדל
            if (!name || !name.trim() || await isInvalidName(name) || /^\s*\(\d+\)\s*$/.test(name)) {
                const baseName = getBaseName(name);
                name = baseName && baseName.trim() && !await isInvalidName(baseName) && !/^\s*\(\d+\)\s*$/.test(baseName) 
                    ? baseName 
                    : `איש קשר ${c.phone.slice(-4)}`;
            }
            
            // וודא שם ייחודי עם סיומת אם צריך
            name = await makeUniqueName(name, usedNames, c.phone);
            
            finalContacts.push({ 
                phone: c.phone, 
                name, 
                email: c.email || '',
                sourceFile: c.sourceFile || '',
                sourceFileId: c.sourceFileId || null,
                originalData: c.originalData || {}
            });
        }

        // שמירת נתוני הניתוח לצפייה עתידית בשיתוף מלא
        const fullDraftData = {
            allData: finalContacts.map(c => ({ name: c.name, phone: c.phone, email: c.email, sourceFile: c.sourceFile, sourceFileId: c.sourceFileId, originalData: c.originalData })),
            conflicts: analysisData?.conflicts || [],
            autoResolved: analysisData?.autoResolved || [],
            rejectedContacts: analysisData?.rejectedContacts || [],
            stats: stats || {}
        };
        
        // עדכון הקבוצה
        await pool.query(
            `UPDATE contact_groups SET name = $1, status = 'ready', draft_data = $3, stats = $4, version = 1 WHERE id = $2`,
            [groupName, groupId, JSON.stringify(fullDraftData), JSON.stringify(stats || {})]
        );
        
        // מחק גרסאות קודמות ושמור גרסה ראשונה חדשה
        await pool.query('DELETE FROM group_versions WHERE group_id = $1', [groupId]);
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
        console.log(`[FINALIZE] Complete: ${finalContacts.length} contacts saved to group ${groupId}`);
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
        const { search, page = 1, limit = 100, sortBy = 'name', sortDir = 'asc' } = req.query;
        const offset = (page - 1) * limit;
        
        let query = 'SELECT * FROM contacts WHERE group_id = $1';
        let params = [req.params.id];
        
        if (search) {
            query += ' AND (full_name ILIKE $2 OR phone ILIKE $2)';
            params.push(`%${search}%`);
        }
        
        // מיון
        const sortColumn = sortBy === 'phone' ? 'phone' : sortBy === 'source' ? 'source_file_name' : 'full_name';
        const sortDirection = sortDir === 'desc' ? 'DESC' : 'ASC';
        query += ` ORDER BY ${sortColumn} ${sortDirection} NULLS LAST`;
        
        query += ' LIMIT $' + (params.length + 1) + ' OFFSET $' + (params.length + 2);
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
    const groupId = req.params.id;
    console.log(`[DELETE GROUP] Starting deletion of group ${groupId}`);
    
    // שלח תשובה מיד - המחיקה תמשיך ברקע
    res.json({ success: true, message: 'Deletion started' });
    
    // פונקציה למחיקה בחלקים עם טיימאאוט והמתנה
    const deleteInChunks = async (tableName, whereClause, chunkSize = 2000) => {
        let totalDeleted = 0;
        let retries = 0;
        const maxRetries = 5;
        
        while (retries < maxRetries) {
            try {
                const result = await pool.query(
                    `DELETE FROM ${tableName} WHERE id IN (SELECT id FROM ${tableName} WHERE ${whereClause} LIMIT ${chunkSize})`,
                    [groupId]
                );
                
                if (result.rowCount === 0) break;
                
                totalDeleted += result.rowCount;
                console.log(`[DELETE GROUP] Deleted ${totalDeleted} from ${tableName}...`);
                
                // המתן מעט בין חלקים כדי לא לעמיס על ה-DB
                await new Promise(r => setTimeout(r, 100));
                retries = 0; // אפס את הרטריות אחרי הצלחה
                
            } catch (err) {
                retries++;
                console.log(`[DELETE GROUP] Retry ${retries}/${maxRetries} for ${tableName}: ${err.message}`);
                await new Promise(r => setTimeout(r, 1000 * retries)); // המתנה מוגברת
            }
        }
        
        return totalDeleted;
    };
    
    try {
        // מחק גרסאות
        try {
            await pool.query('DELETE FROM group_versions WHERE group_id = $1', [groupId]);
            console.log(`[DELETE GROUP] Deleted versions`);
        } catch (e) {
            console.log(`[DELETE GROUP] Versions delete error (non-critical): ${e.message}`);
        }
        
        // מחק אנשי קשר שנדחו
        try {
            await pool.query('DELETE FROM rejected_contacts WHERE group_id = $1', [groupId]);
            console.log(`[DELETE GROUP] Deleted rejected contacts`);
        } catch (e) { }
        
        // מחק אנשי קשר בחלקים
        const deleted = await deleteInChunks('contacts', 'group_id = $1', 2000);
        console.log(`[DELETE GROUP] Total deleted ${deleted} contacts`);
        
        // מחק את הקבוצה עצמה
        await pool.query('DELETE FROM contact_groups WHERE id = $1', [groupId]);
        console.log(`[DELETE GROUP] Group ${groupId} deleted successfully`);
    } catch (err) {
        console.error('[DELETE GROUP] Error:', err.message);
    }
});

// החזרת רשימה שמורה למצב טיוטה
app.post('/api/groups/:id/revert-to-draft', auth, async (req, res) => {
    try {
        const groupId = req.params.id;
        console.log(`[REVERT] Starting revert to draft for group ${groupId}`);
        
        // קבל את כל אנשי הקשר של הקבוצה
        const contactsRes = await pool.query(
            `SELECT full_name, phone, phone_normalized, email, source_file_id, source_file_name, original_data 
             FROM contacts WHERE group_id = $1`,
            [groupId]
        );
        
        const contacts = contactsRes.rows;
        console.log(`[REVERT] Found ${contacts.length} contacts`);
        
        // בניית מבנה הטיוטה
        const allData = contacts.map(c => ({
            name: c.full_name,
            phone: c.phone_normalized || c.phone,
            phoneRaw: c.phone,
            email: c.email || '',
            sourceFile: c.source_file_name || '',
            sourceFileId: c.source_file_id,
            originalData: c.original_data || {}
        }));
        
        const draftData = {
            allData,
            conflicts: [],
            autoResolved: [],
            rejectedContacts: [],
            stats: {
                totalParsed: contacts.length,
                totalValid: contacts.length,
                totalRejected: 0,
                totalDuplicates: 0,
                byFile: []
            }
        };
        
        // עדכן את הקבוצה לסטטוס טיוטה
        await pool.query(
            `UPDATE contact_groups SET status = 'draft', draft_data = $2 WHERE id = $1`,
            [groupId, JSON.stringify(draftData)]
        );
        
        console.log(`[REVERT] Group ${groupId} reverted to draft`);
        res.json({ success: true, contactsCount: contacts.length });
    } catch (err) {
        console.error('[REVERT] Error:', err);
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
    const { id, versionId } = req.params;
    
    try {
        // קבל את ה-snapshot
        const v = await pool.query('SELECT * FROM group_versions WHERE id = $1 AND group_id = $2', [versionId, id]);
        if (!v.rows[0]) return res.status(404).json({ error: 'Version not found' });
        
        const snapshot = v.rows[0].contacts_snapshot;
        console.log(`[RESTORE] Starting restore version ${versionId} for group ${id}, ${snapshot?.length || 0} contacts`);
        
        // שלח תשובה מיד
        res.json({ success: true, restoredCount: snapshot?.length || 0, message: 'Restore started' });
        
        // מחק אנשי קשר קיימים בחלקים
        let deleted = 0;
        while (true) {
            const result = await pool.query(
                'DELETE FROM contacts WHERE id IN (SELECT id FROM contacts WHERE group_id = $1 LIMIT 2000)', 
                [id]
            );
            if (result.rowCount === 0) break;
            deleted += result.rowCount;
            console.log(`[RESTORE] Deleted ${deleted} contacts...`);
            await new Promise(r => setTimeout(r, 50));
        }
        console.log(`[RESTORE] Total deleted ${deleted} contacts`);
        
        // שחזר מה-snapshot בבאצ'ים
        if (snapshot && snapshot.length > 0) {
            const truncate = (s, max) => s && s.length > max ? s.substring(0, max) : s;
            let batch = [];
            let inserted = 0;
            
            for (const c of snapshot) {
                batch.push([
                    id, 
                    truncate(c.full_name, 250), 
                    c.phone, 
                    c.phone_normalized || c.phone, 
                    truncate(c.email, 250), 
                    c.source_file_id, 
                    truncate(c.source_file_name, 450), 
                    JSON.stringify(c.original_data || {}), 
                    JSON.stringify(c.metadata || {})
                ]);
                
                if (batch.length >= 1000) {
                    await pool.query(
                        `INSERT INTO contacts (group_id, full_name, phone, phone_normalized, email, source_file_id, source_file_name, original_data, metadata) 
                         SELECT * FROM UNNEST ($1::int[], $2::text[], $3::text[], $4::text[], $5::text[], $6::int[], $7::text[], $8::jsonb[], $9::jsonb[])`,
                        [batch.map(r=>r[0]), batch.map(r=>r[1]), batch.map(r=>r[2]), batch.map(r=>r[3]), batch.map(r=>r[4]), batch.map(r=>r[5]), batch.map(r=>r[6]), batch.map(r=>r[7]), batch.map(r=>r[8])]
                    );
                    inserted += batch.length;
                    console.log(`[RESTORE] Inserted ${inserted} contacts...`);
                    batch = [];
                    await new Promise(r => setTimeout(r, 50));
                }
            }
            
            if (batch.length > 0) {
                await pool.query(
                    `INSERT INTO contacts (group_id, full_name, phone, phone_normalized, email, source_file_id, source_file_name, original_data, metadata) 
                     SELECT * FROM UNNEST ($1::int[], $2::text[], $3::text[], $4::text[], $5::text[], $6::int[], $7::text[], $8::jsonb[], $9::jsonb[])`,
                    [batch.map(r=>r[0]), batch.map(r=>r[1]), batch.map(r=>r[2]), batch.map(r=>r[3]), batch.map(r=>r[4]), batch.map(r=>r[5]), batch.map(r=>r[6]), batch.map(r=>r[7]), batch.map(r=>r[8])]
                );
                inserted += batch.length;
            }
            console.log(`[RESTORE] Total inserted ${inserted} contacts`);
        }
        
        // עדכן סטטיסטיקות
        await pool.query('UPDATE contact_groups SET stats = $2 WHERE id = $1', [id, JSON.stringify(v.rows[0].stats || {})]);
        console.log(`[RESTORE] Restore completed for group ${id}`);
        
    } catch (err) {
        console.error('[RESTORE] Error:', err.message);
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
                
                let name = await cleanName(item.mapping.nameFields.map(f => row[f] || '').join(' '));
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
                // בדוק אם יש מספרי טלפון מאוחדים
                const mergedPhones = c.original_data?.mergedPhones;
                if (mergedPhones && mergedPhones.length > 1) {
                    mergedPhones.forEach(mp => {
                        out += `"${c.full_name}","${mp.phone}","${c.email || ''}"\n`;
                    });
                } else {
                    out += `"${c.full_name}","${c.phone}","${c.email || ''}"\n`;
                }
            });
        } else {
            r.rows.forEach(c => {
                out += `BEGIN:VCARD\nVERSION:3.0\nFN:${c.full_name}\n`;
                
                // בדוק אם יש מספרי טלפון מאוחדים
                const mergedPhones = c.original_data?.mergedPhones;
                if (mergedPhones && mergedPhones.length > 1) {
                    mergedPhones.forEach(mp => {
                        const type = mp.label === 'עבודה' ? 'WORK' : mp.label === 'בית' ? 'HOME' : 'CELL';
                        out += `TEL;TYPE=${type}:${mp.phone}\n`;
                    });
                } else {
                    out += `TEL;TYPE=CELL:${c.phone}\n`;
                }
                
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

// ==================== SHARING ====================

// יצירת/קבלת לינק שיתוף (תמיד מצב מורחב)
app.post('/api/groups/:id/share', auth, async (req, res) => {
    try {
        const groupId = req.params.id;
        const mode = 'full'; // תמיד שיתוף מורחב
        
        let r = await pool.query('SELECT share_token FROM contact_groups WHERE id = $1', [groupId]);
        
        let token = r.rows[0]?.share_token;
        
        // אם אין טוקן, צור טוקן חדש
        if (!token) {
            token = crypto.randomBytes(32).toString('hex');
        }
        
        await pool.query('UPDATE contact_groups SET share_token = $1, share_mode = $2 WHERE id = $3', [token, mode, groupId]);
        
        const url = `/share-full/${token}`;
        res.json({ token, url, mode });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// ביטול שיתוף
app.delete('/api/groups/:id/share', auth, async (req, res) => {
    try {
        await pool.query('UPDATE contact_groups SET share_token = NULL WHERE id = $1', [req.params.id]);
        res.json({ success: true });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// דף שיתוף ציבורי - הפנה תמיד לשיתוף מורחב
app.get('/share/:token', async (req, res) => {
    res.redirect(`/share-full/${req.params.token}`);
});

// דף שיתוף ציבורי - מורחב (עם עריכה מלאה)
app.get('/share-full/:token', async (req, res) => {
    try {
        const r = await pool.query('SELECT id FROM contact_groups WHERE share_token = $1', [req.params.token]);
        if (!r.rows[0]) return res.status(404).send('הקישור לא נמצא או פג תוקף');
        res.sendFile(path.join(__dirname, 'share-full.html'));
    } catch (err) {
        res.status(500).send('שגיאה');
    }
});

// API ציבורי - קבלת פרטי קבוצה
app.get('/api/public/group/:token', async (req, res) => {
    try {
        const g = await pool.query(`
            SELECT id, name, version, stats, 
                   to_char(updated_at, 'DD/MM/YYYY HH24:MI') as updated_at_formatted
            FROM contact_groups WHERE share_token = $1 AND status = 'ready'
        `, [req.params.token]);
        
        if (!g.rows[0]) return res.status(404).json({ error: 'Not found' });
        
        const contacts = await pool.query(
            'SELECT id, full_name, phone, email FROM contacts WHERE group_id = $1 ORDER BY full_name',
            [g.rows[0].id]
        );
        
        res.json({ ...g.rows[0], contacts: contacts.rows });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// API ציבורי - עדכון שם איש קשר
app.put('/api/public/contact/:token/:contactId', async (req, res) => {
    try {
        const { full_name } = req.body;
        if (!full_name || !full_name.trim()) {
            return res.status(400).json({ error: 'Name is required' });
        }
        
        // וודא שאיש הקשר שייך לקבוצה עם הטוקן הזה
        const verify = await pool.query(`
            SELECT c.id FROM contacts c 
            JOIN contact_groups g ON c.group_id = g.id 
            WHERE g.share_token = $1 AND c.id = $2
        `, [req.params.token, req.params.contactId]);
        
        if (!verify.rows[0]) return res.status(404).json({ error: 'Not found' });
        
        await pool.query('UPDATE contacts SET full_name = $1 WHERE id = $2', [full_name.trim(), req.params.contactId]);
        res.json({ success: true });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// API ציבורי - כפילויות
app.get('/api/public/duplicates/:token', async (req, res) => {
    try {
        const g = await pool.query('SELECT id FROM contact_groups WHERE share_token = $1', [req.params.token]);
        if (!g.rows[0]) return res.status(404).json({ error: 'Not found' });
        
        const r = await pool.query(`
            SELECT full_name, array_agg(id) as ids, count(*) as count
            FROM contacts WHERE group_id = $1
            GROUP BY full_name HAVING count(*) > 1
            ORDER BY count DESC, full_name
        `, [g.rows[0].id]);
        
        res.json({ duplicates: r.rows, totalDuplicateNames: r.rows.length });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// API ציבורי - תיקון כפילויות
app.post('/api/public/fix-duplicates/:token', async (req, res) => {
    try {
        const g = await pool.query('SELECT id FROM contact_groups WHERE share_token = $1', [req.params.token]);
        if (!g.rows[0]) return res.status(404).json({ error: 'Not found' });
        
        const groupId = g.rows[0].id;
        const dupsRes = await pool.query(`
            SELECT full_name, array_agg(id ORDER BY id) as ids
            FROM contacts WHERE group_id = $1
            GROUP BY full_name HAVING count(*) > 1
        `, [groupId]);
        
        let fixed = 0;
        for (const dup of dupsRes.rows) {
            const ids = dup.ids;
            for (let i = 1; i < ids.length; i++) {
                const newName = `${dup.full_name} (${i + 1})`;
                await pool.query('UPDATE contacts SET full_name = $1 WHERE id = $2', [newName, ids[i]]);
                fixed++;
            }
        }
        
        res.json({ success: true, fixed });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// API ציבורי - מחיקת שם והוספה לרשימה שחורה + עדכון כל הדומים
app.post('/api/public/clear-name/:token/:contactId', async (req, res) => {
    try {
        // וודא שאיש הקשר שייך לקבוצה עם הטוקן הזה
        const verify = await pool.query(`
            SELECT c.id, c.full_name, c.phone, c.group_id FROM contacts c 
            JOIN contact_groups g ON c.group_id = g.id 
            WHERE g.share_token = $1 AND c.id = $2
        `, [req.params.token, req.params.contactId]);
        
        if (!verify.rows[0]) return res.status(404).json({ error: 'Not found' });
        
        const oldName = verify.rows[0].full_name;
        const phone = verify.rows[0].phone || '';
        const groupId = verify.rows[0].group_id;
        const defaultName = `איש קשר ${phone.slice(-4)}`;
        
        // עדכן את השם לדיפולטיבי
        await pool.query('UPDATE contacts SET full_name = $1 WHERE id = $2', [defaultName, req.params.contactId]);
        
        let updatedCount = 1;
        const baseName = getBaseName(oldName);
        
        // הוסף את השם הישן לרשימה השחורה ועדכן את כל הדומים
        if (baseName && baseName.trim() && !baseName.startsWith('איש קשר')) {
            await pool.query(
                'INSERT INTO invalid_names (name, pattern_type) VALUES ($1, $2) ON CONFLICT DO NOTHING',
                [baseName.trim(), 'exact']
            );
            invalidNamesCache = null;
            
            // מצא ועדכן את כל אנשי הקשר עם שם דומה
            const similarContacts = await pool.query(
                `SELECT id, full_name, phone FROM contacts 
                 WHERE group_id = $1 AND id != $2 AND (
                     full_name = $3 OR 
                     full_name ~ ('^' || $3 || '\\s*\\(\\d+\\)$')
                 )`,
                [groupId, req.params.contactId, baseName]
            );
            
            for (const c of similarContacts.rows) {
                const newDefault = `איש קשר ${c.phone?.slice(-4) || Math.random().toString().slice(2, 6)}`;
                await pool.query('UPDATE contacts SET full_name = $1 WHERE id = $2', [newDefault, c.id]);
                updatedCount++;
            }
        }
        
        res.json({ success: true, newName: defaultName, addedToBlacklist: baseName, updatedCount });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// API ציבורי - ייצוא VCF
app.get('/api/public/export/:token', async (req, res) => {
    try {
        const g = await pool.query('SELECT id, name FROM contact_groups WHERE share_token = $1', [req.params.token]);
        if (!g.rows[0]) return res.status(404).json({ error: 'Not found' });
        
        const contacts = await pool.query('SELECT full_name, phone, email, original_data FROM contacts WHERE group_id = $1', [g.rows[0].id]);
        
        let vcf = '';
        contacts.rows.forEach(c => {
            vcf += `BEGIN:VCARD\nVERSION:3.0\nFN:${c.full_name}\n`;
            
            // בדוק אם יש מספרי טלפון מאוחדים
            const mergedPhones = c.original_data?.mergedPhones;
            if (mergedPhones && mergedPhones.length > 1) {
                mergedPhones.forEach(mp => {
                    const type = mp.label === 'עבודה' ? 'WORK' : mp.label === 'בית' ? 'HOME' : 'CELL';
                    vcf += `TEL;TYPE=${type}:${mp.phone}\n`;
                });
            } else {
                vcf += `TEL;TYPE=CELL:${c.phone}\n`;
            }
            
            if (c.email) vcf += `EMAIL:${c.email}\n`;
            vcf += `END:VCARD\n`;
        });
        
        res.setHeader('Content-Type', 'text/vcard; charset=utf-8');
        res.setHeader('Content-Disposition', `attachment; filename="${g.rows[0].name}.vcf"`);
        res.send('\ufeff' + vcf);
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// ==================== PUBLIC FULL SHARE MODE API ====================

// בדיקת הרשאות שיתוף מלא
const verifyFullShare = async (token) => {
    const r = await pool.query('SELECT id, share_mode FROM contact_groups WHERE share_token = $1', [token]);
    if (!r.rows[0]) return null;
    if (r.rows[0].share_mode !== 'full') return null;
    return r.rows[0].id;
};

// קבלת נתוני טיוטה מלאים לשיתוף
app.get('/api/public/full-data/:token', async (req, res) => {
    try {
        const groupId = await verifyFullShare(req.params.token);
        if (!groupId) return res.status(403).json({ error: 'אין הרשאה לתצוגה מלאה' });
        
        const g = await pool.query(`
            SELECT id, name, status, draft_data, stats, version,
                   to_char(updated_at, 'DD/MM/YYYY HH24:MI') as updated_at_formatted
            FROM contact_groups WHERE id = $1
        `, [groupId]);
        
        const group = g.rows[0];
        
        // אם יש draft_data, החזר אותו
        if (group.draft_data) {
            return res.json({
                ...group.draft_data,
                groupId: group.id,
                targetGroupName: group.name,
                status: group.status
            });
        }
        
        // אחרת, בנה את הנתונים מאנשי הקשר
        const contactsRes = await pool.query(
            `SELECT full_name, phone, phone_normalized, email, source_file_name, source_file_id, original_data 
             FROM contacts WHERE group_id = $1`,
            [groupId]
        );
        
        const allData = contactsRes.rows.map(c => ({
            name: c.full_name,
            phone: c.phone_normalized || c.phone,
            phoneRaw: c.phone,
            email: c.email || '',
            sourceFile: c.source_file_name || '',
            sourceFileId: c.source_file_id,
            originalData: c.original_data || {}
        }));
        
        res.json({
            allData,
            conflicts: [],
            autoResolved: [],
            rejectedContacts: [],
            stats: group.stats || { totalParsed: allData.length, totalValid: allData.length },
            groupId: group.id,
            targetGroupName: group.name,
            status: group.status
        });
    } catch (err) {
        console.error('[PUBLIC FULL] Error:', err);
        res.status(500).json({ error: err.message });
    }
});

// שמירת טיוטה בשיתוף מלא
app.post('/api/public/save-draft/:token', async (req, res) => {
    try {
        const groupId = await verifyFullShare(req.params.token);
        if (!groupId) return res.status(403).json({ error: 'אין הרשאה' });
        
        const { allData, conflicts, autoResolved, rejectedContacts, stats } = req.body;
        
        const draftData = { allData, conflicts, autoResolved, rejectedContacts, stats };
        await pool.query(
            `UPDATE contact_groups SET draft_data = $2, status = 'draft' WHERE id = $1`,
            [groupId, JSON.stringify(draftData)]
        );
        
        res.json({ success: true });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// קבלת הגדרות לשיתוף מלא
app.get('/api/public/settings/:token', async (req, res) => {
    try {
        const groupId = await verifyFullShare(req.params.token);
        if (!groupId) return res.status(403).json({ error: 'אין הרשאה' });
        
        const [cleaningRules, nameRules, invalidNames] = await Promise.all([
            pool.query("SELECT value FROM system_settings WHERE key = 'cleaning_rules'"),
            pool.query("SELECT value FROM system_settings WHERE key = 'name_rules'"),
            pool.query("SELECT id, name, pattern_type FROM invalid_names ORDER BY id")
        ]);
        
        res.json({
            cleaningRules: cleaningRules.rows[0]?.value || getDefaultCleaningRules(),
            nameRules: nameRules.rows[0]?.value || {},
            invalidNames: invalidNames.rows
        });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// עדכון הגדרות מקליינט (שיתוף מלא)
app.put('/api/public/settings/:token', async (req, res) => {
    try {
        const groupId = await verifyFullShare(req.params.token);
        if (!groupId) return res.status(403).json({ error: 'אין הרשאה' });
        
        const { cleaningRules, nameRules } = req.body;
        
        if (cleaningRules) {
            await pool.query(
                `INSERT INTO system_settings (key, value) VALUES ('cleaning_rules', $1)
                 ON CONFLICT (key) DO UPDATE SET value = $1`,
                [JSON.stringify(cleaningRules)]
            );
            cleaningRulesCache = null;
        }
        
        if (nameRules) {
            await pool.query(
                `INSERT INTO system_settings (key, value) VALUES ('name_rules', $1)
                 ON CONFLICT (key) DO UPDATE SET value = $1`,
                [JSON.stringify(nameRules)]
            );
            nameRulesCache = null;
        }
        
        res.json({ success: true });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// הוספת שם לרשימה שחורה מקליינט
app.post('/api/public/invalid-names/:token', async (req, res) => {
    try {
        const groupId = await verifyFullShare(req.params.token);
        if (!groupId) return res.status(403).json({ error: 'אין הרשאה' });
        
        const { name, patternType = 'exact' } = req.body;
        if (!name) return res.status(400).json({ error: 'חסר שם' });
        
        await pool.query(
            'INSERT INTO invalid_names (name, pattern_type) VALUES ($1, $2) ON CONFLICT DO NOTHING',
            [name.trim(), patternType]
        );
        invalidNamesCache = null;
        
        res.json({ success: true });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// סיום ושמירה סופית מקליינט (שיתוף מלא)
app.post('/api/public/finalize/:token', async (req, res) => {
    try {
        const groupId = await verifyFullShare(req.params.token);
        if (!groupId) return res.status(403).json({ error: 'אין הרשאה' });
        
        const { contacts, stats, analysisData } = req.body;
        console.log(`[PUBLIC FINALIZE] Starting: groupId=${groupId}, contacts=${contacts?.length}`);
        
        const resolutions = await pool.query('SELECT phone, resolved_name FROM import_resolutions');
        const resMap = new Map(resolutions.rows.map(r => [r.phone, r.resolved_name]));

        const finalContacts = [];
        const usedNames = new Set();

        for (const c of contacts) {
            let name = resMap.get(c.phone) || c.name;
            
            if (!name || !name.trim() || await isInvalidName(name) || /^\s*\(\d+\)\s*$/.test(name)) {
                const baseName = getBaseName(name);
                name = baseName && baseName.trim() && !await isInvalidName(baseName) && !/^\s*\(\d+\)\s*$/.test(baseName) 
                    ? baseName 
                    : `איש קשר ${c.phone.slice(-4)}`;
            }
            
            name = await makeUniqueName(name, usedNames, c.phone);
            
            finalContacts.push({ 
                phone: c.phone, 
                name, 
                email: c.email || '',
                sourceFile: c.sourceFile || '',
                sourceFileId: c.sourceFileId || null,
                originalData: c.originalData || {}
            });
        }

        // מחק אנשי קשר קיימים
        await pool.query('DELETE FROM contacts WHERE group_id = $1', [groupId]);
        
        // הכנס חדשים
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
        
        // שמירת נתוני הניתוח לצפייה עתידית
        const fullDraftData = {
            allData: finalContacts.map(c => ({ name: c.name, phone: c.phone, email: c.email, sourceFile: c.sourceFile, sourceFileId: c.sourceFileId, originalData: c.originalData })),
            conflicts: analysisData?.conflicts || [],
            autoResolved: analysisData?.autoResolved || [],
            rejectedContacts: analysisData?.rejectedContacts || [],
            stats: stats || {}
        };
        
        // עדכן סטטוס
        await pool.query(
            `UPDATE contact_groups SET status = 'ready', draft_data = $2, stats = $3 WHERE id = $1`,
            [groupId, JSON.stringify(fullDraftData), JSON.stringify(stats || {})]
        );
        
        console.log(`[PUBLIC FINALIZE] Complete: ${finalContacts.length} contacts saved`);
        res.json({ success: true, contactsCount: finalContacts.length });
    } catch (err) {
        console.error('[PUBLIC FINALIZE] Error:', err);
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

// מחיקת שם והוספה לרשימה שחורה + עדכון כל אנשי הקשר עם אותו שם
app.post('/api/contacts/:id/clear', auth, async (req, res) => {
    try {
        const contact = await pool.query('SELECT full_name, phone, group_id FROM contacts WHERE id = $1', [req.params.id]);
        if (!contact.rows[0]) return res.status(404).json({ error: 'Not found' });
        
        const oldName = contact.rows[0].full_name;
        const phone = contact.rows[0].phone || '';
        const groupId = contact.rows[0].group_id;
        const defaultName = `איש קשר ${phone.slice(-4)}`;
        
        console.log(`[CLEAR] Contact ${req.params.id}: oldName="${oldName}", phone="${phone}", newName="${defaultName}"`);
        
        // עדכן את השם הנוכחי
        await pool.query('UPDATE contacts SET full_name = $1 WHERE id = $2', [defaultName, req.params.id]);
        
        let updatedCount = 1;
        const baseName = getBaseName(oldName);
        
        // הוסף לרשימה שחורה והחלף את כל אנשי הקשר עם שם דומה
        if (baseName && baseName.trim() && !baseName.startsWith('איש קשר')) {
            console.log(`[CLEAR] Adding to blacklist: "${baseName.trim()}"`);
            await pool.query(
                'INSERT INTO invalid_names (name, pattern_type) VALUES ($1, $2) ON CONFLICT DO NOTHING',
                [baseName.trim(), 'exact']
            );
            invalidNamesCache = null;
            
            // מצא את כל אנשי הקשר עם אותו שם או שם עם (X) באותה קבוצה
            const similarContacts = await pool.query(
                `SELECT id, full_name, phone FROM contacts 
                 WHERE group_id = $1 AND id != $2 AND (
                     full_name = $3 OR 
                     full_name ~ ('^' || $3 || '\\s*\\(\\d+\\)$')
                 )`,
                [groupId, req.params.id, baseName]
            );
            
            // עדכן את כולם לשמות דיפולטיביים
            for (const c of similarContacts.rows) {
                const newDefault = `איש קשר ${c.phone?.slice(-4) || Math.random().toString().slice(2, 6)}`;
                await pool.query('UPDATE contacts SET full_name = $1 WHERE id = $2', [newDefault, c.id]);
                updatedCount++;
            }
        }
        
        res.json({ success: true, newName: defaultName, addedToBlacklist: baseName, updatedCount });
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

// כללי ניקוי שמות
app.get('/api/settings/cleaning-rules', auth, async (req, res) => {
    try {
        const r = await pool.query("SELECT value FROM system_settings WHERE key = 'cleaning_rules'");
        res.json(r.rows[0]?.value || getDefaultCleaningRules());
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

app.put('/api/settings/cleaning-rules', auth, async (req, res) => {
    try {
        await pool.query(
            `INSERT INTO system_settings (key, value, updated_at) VALUES ('cleaning_rules', $1, CURRENT_TIMESTAMP)
             ON CONFLICT (key) DO UPDATE SET value = $1, updated_at = CURRENT_TIMESTAMP`,
            [JSON.stringify(req.body)]
        );
        cleaningRulesCache = null;
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

// ==================== DATABASE MIGRATIONS ====================

async function runMigrations() {
    try {
        // הוסף עמודת share_mode אם לא קיימת
        await pool.query(`
            ALTER TABLE contact_groups 
            ADD COLUMN IF NOT EXISTS share_mode VARCHAR(20) DEFAULT 'simple'
        `);
        console.log('[MIGRATIONS] Database migrations completed');
    } catch (err) {
        console.error('[MIGRATIONS] Error:', err.message);
    }
}

// ==================== START SERVER ====================

app.listen(3377, async () => {
    console.log('[VCF Server] Running on port 3377');
    console.log('[VCF Server] Database:', process.env.DB_HOST || '127.0.0.1', ':', process.env.DB_PORT || 3378);
    await runMigrations();
});
