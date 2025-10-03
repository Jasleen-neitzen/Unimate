const express = require('express');
const fs = require('fs').promises;
const path = require('path');
const session = require('express-session');
const FileStore = require('session-file-store')(session);
const ical = require('node-ical');
const { DateTime } = require('luxon');
const bcrypt = require('bcrypt');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const crypto = require('crypto');
const multer = require('multer');
const mammoth = require('mammoth');
const pdfParse = require('pdf-parse');
const axios = require('axios');
const speakeasy = require('speakeasy');
const qrcode = require('qrcode');

const app = express();
const PORT = process.env.PORT || 4000;
const SESSION_SECRET = process.env.SESSION_SECRET || crypto.randomBytes(32).toString('hex');
const ENCRYPTION_KEY = process.env.ENCRYPTION_KEY || crypto.randomBytes(32);

// Security headers
app.use(helmet({
    contentSecurityPolicy: {
        directives: {
            defaultSrc: ["'self'"],
            styleSrc: ["'self'", "'unsafe-inline'"],
            scriptSrc: ["'self'", "'unsafe-inline'"]
        }
    }
}));

// Rate limiting
const loginLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 5,
    message: 'Too many login attempts, please try again later.'
});

const calendarLimiter = rateLimit({
    windowMs: 60 * 1000,
    max: 10,
    message: 'Too many requests, please slow down.'
});

// Session with File storage (persists across restarts!)
app.use(session({
    secret: SESSION_SECRET,
    resave: false,
    saveUninitialized: false,
    name: 'sessionId',
    store: new FileStore({
        path: './sessions',
        ttl: 3600,
        retries: 0
    }),
    cookie: {
        httpOnly: true,
        secure: process.env.NODE_ENV === 'production',
        maxAge: 3600000,
        sameSite: 'strict'
    }
}));

app.use(express.urlencoded({ extended: true, limit: '10kb' }));
app.use(express.json({ limit: '10kb' }));

// File upload configuration
const storage = multer.diskStorage({
    destination: async (req, file, cb) => {
        const userFolder = path.join(__dirname, 'uploads', req.session.username);
        await fs.mkdir(userFolder, { recursive: true });
        cb(null, userFolder);
    },
    filename: (req, file, cb) => {
        const uniqueName = Date.now() + '-' + file.originalname;
        cb(null, uniqueName);
    }
});

const upload = multer({
    storage: storage,
    limits: { fileSize: 10 * 1024 * 1024 },
    fileFilter: (req, file, cb) => {
        const allowedTypes = ['.pdf', '.doc', '.docx', '.txt'];
        const ext = path.extname(file.originalname).toLowerCase();
        if (allowedTypes.includes(ext)) {
            cb(null, true);
        } else {
            cb(new Error('Only PDF, DOC, DOCX, and TXT files allowed'));
        }
    }
});

// Cache for Canvas API responses
const canvasCache = new Map();
const CACHE_TTL = 5 * 60 * 1000; // 5 minutes

// Encryption for Canvas tokens
function encryptToken(token) {
    const iv = crypto.randomBytes(16);
    const cipher = crypto.createCipheriv('aes-256-cbc', ENCRYPTION_KEY, iv);
    let encrypted = cipher.update(token, 'utf8', 'hex');
    encrypted += cipher.final('hex');
    return iv.toString('hex') + ':' + encrypted;
}

function decryptToken(encryptedToken) {
    const parts = encryptedToken.split(':');
    const iv = Buffer.from(parts[0], 'hex');
    const encrypted = parts[1];
    const decipher = crypto.createDecipheriv('aes-256-cbc', ENCRYPTION_KEY, iv);
    let decrypted = decipher.update(encrypted, 'hex', 'utf8');
    decrypted += decipher.final('utf8');
    return decrypted;
}

// Helper functions
function escapeHtml(text) {
    if (!text) return '';
    return String(text).replace(/[&<>"']/g, (char) => ({
        '&': '&amp;',
        '<': '&lt;',
        '>': '&gt;',
        '"': '&quot;',
        "'": '&#39;'
    })[char]);
}

function isValidUsername(username) {
    if (!username || typeof username !== 'string') return false;
    if (username.length < 3 || username.length > 30) return false;
    return /^[a-zA-Z0-9_]+$/.test(username);
}

function isValidPassword(password) {
    if (!password || typeof password !== 'string') return false;
    return password.length >= 8 && password.length <= 128;
}

function isValidCalendarUrl(url) {
    try {
        const parsed = new URL(url);
        if (parsed.protocol !== 'https:' && parsed.protocol !== 'http:') return false;
        const hostname = parsed.hostname.toLowerCase();
        if (hostname === 'localhost' || hostname === '127.0.0.1' || hostname === '::1') return false;
        if (hostname.startsWith('192.168.') || hostname.startsWith('10.')) return false;
        return true;
    } catch {
        return false;
    }
}

async function loadUsers() {
    try {
        const data = await fs.readFile('users.txt', 'utf-8');
        const users = {};
        data.split('\n').forEach(line => {
            const parts = line.split(',');
            if (parts.length >= 2) {
                const username = parts[0];
                const hashedPassword = parts[1];
                const mfaSecret = parts[2] || null;
                const encryptedCanvasToken = parts[3] || null;
                users[username] = { 
                    hashedPassword: hashedPassword.trim(), 
                    mfaSecret,
                    encryptedCanvasToken
                };
            }
        });
        return users;
    } catch (err) {
        if (err.code === 'ENOENT') return {};
        throw err;
    }
}

async function saveUser(username, hashedPassword, mfaSecret = null, encryptedCanvasToken = null) {
    const users = await loadUsers();
    users[username] = { hashedPassword, mfaSecret, encryptedCanvasToken };
    
    const lines = Object.keys(users).map(user => 
        `${user},${users[user].hashedPassword}${users[user].mfaSecret ? ',' + users[user].mfaSecret : ''}${users[user].encryptedCanvasToken ? ',' + users[user].encryptedCanvasToken : ''}`
    );
    
    await fs.writeFile('users.txt', lines.join('\n') + '\n');
}

async function updateUserCanvasToken(username, encryptedToken) {
    const users = await loadUsers();
    if (users[username]) {
        users[username].encryptedCanvasToken = encryptedToken;
        const lines = Object.keys(users).map(user => 
            `${user},${users[user].hashedPassword}${users[user].mfaSecret ? ',' + users[user].mfaSecret : ''}${users[user].encryptedCanvasToken ? ',' + users[user].encryptedCanvasToken : ''}`
        );
        await fs.writeFile('users.txt', lines.join('\n') + '\n');
    }
}

async function fetchIcsEvents(url, timeout = 10000) {
    return new Promise((resolve, reject) => {
        const timer = setTimeout(() => reject(new Error('Timeout')), timeout);
        ical.fromURL(url, {}, (err, data) => {
            clearTimeout(timer);
            if (err) return reject(err);
            try {
                const events = Object.values(data).filter(e => e && e.type === 'VEVENT');
                resolve(events.slice(0, 1000));
            } catch {
                reject(new Error('Invalid format'));
            }
        });
    });
}

function eventsForDate(events, tz = 'Australia/Sydney', target = DateTime.now().setZone(tz)) {
    const day = target.toISODate();
    return events
        .filter(e => e.start)
        .filter(e => {
            try {
                let eventDate;
                if (typeof e.start === 'string') {
                    eventDate = DateTime.fromISO(e.start, { zone: 'utc' }).setZone(tz);
                } else {
                    eventDate = DateTime.fromJSDate(e.start).setZone(tz);
                }
                return eventDate.toISODate() === day;
            } catch {
                return false;
            }
        })
        .map(e => {
            try {
                let eventDate;
                if (typeof e.start === 'string') {
                    eventDate = DateTime.fromISO(e.start, { zone: 'utc' }).setZone(tz);
                } else {
                    eventDate = DateTime.fromJSDate(e.start).setZone(tz);
                }
                const start = eventDate.toFormat('h:mm a');
                const summary = escapeHtml(e.summary || 'Untitled');
                return `${summary} ${start}`;
            } catch {
                return 'Invalid event';
            }
        })
        .slice(0, 50);
}

function getClassLocations(events, tz = 'Australia/Sydney', target = DateTime.now().setZone(tz)) {
    const day = target.toISODate();
    return events
        .filter(e => e.start && e.location)
        .filter(e => {
            try {
                let eventDate;
                if (typeof e.start === 'string') {
                    eventDate = DateTime.fromISO(e.start, { zone: 'utc' }).setZone(tz);
                } else {
                    eventDate = DateTime.fromJSDate(e.start).setZone(tz);
                }
                return eventDate.toISODate() === day;
            } catch {
                return false;
            }
        })
        .map(e => {
            try {
                let eventDate;
                if (typeof e.start === 'string') {
                    eventDate = DateTime.fromISO(e.start, { zone: 'utc' }).setZone(tz);
                } else {
                    eventDate = DateTime.fromJSDate(e.start).setZone(tz);
                }
                const start = eventDate.toFormat('h:mm a');
                const summary = escapeHtml(e.summary || 'Untitled');
                const location = escapeHtml(e.location || 'Location not specified');
                return {
                    name: summary,
                    time: start,
                    location: location,
                    raw: e
                };
            } catch {
                return null;
            }
        })
        .filter(e => e !== null)
        .slice(0, 50);
}

function findClassLocation(events, className, tz = 'Australia/Sydney', target = DateTime.now().setZone(tz)) {
    const classesWithLocations = getClassLocations(events, tz, target);
    
    if (!className || className.length < 2) {
        return classesWithLocations;
    }
    
    const searchTerms = className.toLowerCase().split(/\s+/).filter(w => w.length > 1);
    
    return classesWithLocations.filter(c => {
        const name = c.name.toLowerCase();
        return searchTerms.some(term => name.includes(term));
    });
}

async function extractTextFromFile(filePath) {
    const ext = path.extname(filePath).toLowerCase();
    try {
        if (ext === '.pdf') {
            const dataBuffer = await fs.readFile(filePath);
            const data = await pdfParse(dataBuffer);
            return data.text;
        } else if (ext === '.docx' || ext === '.doc') {
            const result = await mammoth.extractRawText({ path: filePath });
            return result.value;
        } else if (ext === '.txt') {
            return await fs.readFile(filePath, 'utf-8');
        }
    } catch (err) {
        console.error('Extraction error:', err);
    }
    return null;
}

function generateEnhancedSummary(text, maxLength = 2500) {
    if (!text) return "No content available.";
    text = text.replace(/\s+/g, ' ').trim();
    
    let summary = '';
    
    const todoPatterns = [
        /(?:to[- ]?do|assignment|task|homework|lab|exercise|activity|complete|submit|due).*?(?:\.|$)/gi,
        /(?:you (?:should|must|need to|will)).*?(?:\.|$)/gi
    ];
    
    let todos = [];
    todoPatterns.forEach(pattern => {
        const matches = text.match(pattern);
        if (matches) {
            todos.push(...matches.slice(0, 5));
        }
    });
    
    if (todos.length > 0) {
        summary += '<div style="background: #fff3e0; padding: 12px; border-left: 4px solid #ff9800; margin-bottom: 15px;">';
        summary += '<strong style="color: #e65100;">📌 Tasks & Assignments:</strong><br>';
        todos.slice(0, 5).forEach(todo => {
            summary += `• ${escapeHtml(todo.trim())}<br>`;
        });
        summary += '</div>';
    }
    
    const conceptPattern = /(?:^|\. )([A-Z][a-z]+(?:\s+[A-Z][a-z]+)*)\s+(?:is|are|refers to|means|defines?|represents?)\s+([^.]+\.)/g;
    let concepts = [];
    let match;
    while ((match = conceptPattern.exec(text)) !== null && concepts.length < 5) {
        concepts.push({ term: match[1], definition: match[2] });
    }
    
    if (concepts.length > 0) {
        summary += '<div style="background: #e3f2fd; padding: 12px; border-left: 4px solid #2196f3; margin-bottom: 15px;">';
        summary += '<strong style="color: #1565c0;">💡 Key Concepts:</strong><br>';
        concepts.forEach(concept => {
            summary += `<strong>${escapeHtml(concept.term)}:</strong> ${escapeHtml(concept.definition)}<br>`;
        });
        summary += '</div>';
    }
    
    const objectivePatterns = [
        /(?:learning objectives?|objectives?|goals?|by the end|you will (?:be able to|learn|understand)).*?(?:\.|$)/gi,
        /(?:understand|explain|describe|identify|analyze|apply|create).*?(?:\.|$)/gi
    ];
    
    let objectives = [];
    objectivePatterns.forEach(pattern => {
        const matches = text.match(pattern);
        if (matches) {
            objectives.push(...matches.slice(0, 4));
        }
    });
    
    if (objectives.length > 0) {
        summary += '<div style="background: #e8f5e9; padding: 12px; border-left: 4px solid #4caf50; margin-bottom: 15px;">';
        summary += '<strong style="color: #2e7d32;">🎯 Learning Objectives:</strong><br>';
        objectives.slice(0, 4).forEach(obj => {
            summary += `• ${escapeHtml(obj.trim())}<br>`;
        });
        summary += '</div>';
    }
    
    const datePattern = /(?:due|deadline|submit by|on|before)\s+(?:\w+\s+)?\d{1,2}(?:st|nd|rd|th)?\s+(?:of\s+)?(?:jan|feb|mar|apr|may|jun|jul|aug|sep|oct|nov|dec)[a-z]*\s+\d{4}|(?:due|deadline|submit by).*?(?:\.|$)/gi;
    const dates = text.match(datePattern);
    
    if (dates && dates.length > 0) {
        summary += '<div style="background: #fce4ec; padding: 12px; border-left: 4px solid #e91e63; margin-bottom: 15px;">';
        summary += '<strong style="color: #c2185b;">⏰ Important Dates:</strong><br>';
        dates.slice(0, 3).forEach(date => {
            summary += `• ${escapeHtml(date.trim())}<br>`;
        });
        summary += '</div>';
    }
    
    const sentences = text.match(/[^.!?]+[.!?]+/g) || [text];
    const importantSentences = sentences
        .filter(s => {
            const lower = s.toLowerCase();
            return s.length > 40 && 
                   (lower.includes('important') || 
                    lower.includes('key') || 
                    lower.includes('note') ||
                    lower.includes('remember') ||
                    lower.includes('main') ||
                    lower.includes('essential') ||
                    lower.includes('critical') ||
                    /[A-Z][a-z]+.*(?:is|are|will|can|must)/.test(s));
        })
        .slice(0, 8);
    
    if (importantSentences.length > 0) {
        summary += '<div style="background: #f5f5f5; padding: 12px; border-left: 4px solid #757575; margin-bottom: 15px;">';
        summary += '<strong style="color: #424242;">📖 Main Content:</strong><br>';
        importantSentences.forEach(sentence => {
            summary += `${escapeHtml(sentence.trim())} `;
        });
        summary += '</div>';
    } else {
        summary += '<div style="background: #f5f5f5; padding: 12px; border-left: 4px solid #757575;">';
        summary += '<strong style="color: #424242;">📖 Content Overview:</strong><br>';
        let content = '';
        for (let sentence of sentences.slice(0, 10)) {
            if (content.length >= maxLength) break;
            content += escapeHtml(sentence.trim()) + ' ';
        }
        summary += content || escapeHtml(text.substring(0, maxLength));
        summary += '</div>';
    }
    
    return summary || "Could not generate summary.";
}

async function geocodeLocation(location) {
    try {
        const response = await axios.get('https://nominatim.openstreetmap.org/search', {
            params: { q: location, format: 'json', limit: 1 },
            headers: { 'User-Agent': 'Unimate-App' },
            timeout: 5000
        });
        if (response.data.length > 0) {
            return { lat: response.data[0].lat, lon: response.data[0].lon };
        }
    } catch (err) {
        console.error('Geocoding error:', err.message);
    }
    return null;
}

async function getOpenStreetMapDirections(fromLocation, toLocation) {
    try {
        const fromCoords = await geocodeLocation(fromLocation);
        const toCoords = await geocodeLocation(toLocation);
        
        if (!fromCoords || !toCoords) return null;
        
        const response = await axios.get('https://router.project-osrm.org/route/v1/foot/' + 
            `${fromCoords.lon},${fromCoords.lat};${toCoords.lon},${toCoords.lat}`, {
            params: { overview: 'full', steps: true },
            timeout: 5000
        });
        
        if (response.data.code === 'Ok') {
            const route = response.data.routes[0];
            return {
                duration: Math.round(route.duration / 60) + ' min',
                distance: (route.distance / 1000).toFixed(1) + ' km',
                steps: route.legs[0].steps.map(s => s.maneuver.instruction || 'Continue').filter(s => s !== 'Continue'),
                mapsUrl: `https://www.openstreetmap.org/directions?from=${fromCoords.lat},${fromCoords.lon}&to=${toCoords.lat},${toCoords.lon}`
            };
        }
    } catch (err) {
        console.error('OSM error:', err.message);
    }
    return null;
}

async function fetchAllCanvasCourses(canvasUrl, apiToken) {
    const cacheKey = `courses-${canvasUrl}`;
    
    if (canvasCache.has(cacheKey)) {
        const cached = canvasCache.get(cacheKey);
        if (Date.now() - cached.timestamp < CACHE_TTL) {
            console.log('✅ Using cached courses');
            return cached.data;
        }
    }
    
    try {
        let allCourses = [];
        let page = 1;
        let hasMore = true;
        
        while (hasMore && page <= 5) {
            console.log(`Fetching courses page ${page}...`);
            const response = await axios.get(`${canvasUrl}/api/v1/courses`, {
                headers: { 'Authorization': `Bearer ${apiToken}` },
                params: { 
                    enrollment_state: 'active',
                    per_page: 100,
                    page: page
                },
                timeout: 10000
            });
            
            allCourses.push(...response.data);
            
            const linkHeader = response.headers.link;
            hasMore = linkHeader && linkHeader.includes('rel="next"');
            page++;
        }
        
        console.log(`✅ Fetched ${allCourses.length} courses`);
        
        canvasCache.set(cacheKey, {
            data: allCourses,
            timestamp: Date.now()
        });
        
        return allCourses;
    } catch (err) {
        console.error('Canvas API error:', err.message);
        if (canvasCache.has(cacheKey)) {
            console.warn('⚠️ Canvas API failed, returning stale cache');
            return canvasCache.get(cacheKey).data;
        }
        throw err;
    }
}

async function fetchCanvasModules(canvasUrl, apiToken, courseId) {
    try {
        const response = await axios.get(`${canvasUrl}/api/v1/courses/${courseId}/modules`, {
            headers: { 'Authorization': `Bearer ${apiToken}` },
            params: { include: ['items'], per_page: 100 },
            timeout: 10000
        });
        return response.data;
    } catch (err) {
        console.error('Canvas modules error:', err.message);
        return null;
    }
}

async function fetchCanvasModuleItems(canvasUrl, apiToken, courseId, moduleId) {
    try {
        const response = await axios.get(`${canvasUrl}/api/v1/courses/${courseId}/modules/${moduleId}/items`, {
            headers: { 'Authorization': `Bearer ${apiToken}` },
            params: { per_page: 100 },
            timeout: 10000
        });
        return response.data;
    } catch (err) {
        console.error('Module items error:', err.message);
        return null;
    }
}

async function fetchCanvasPage(canvasUrl, apiToken, courseId, pageUrl) {
    try {
        const response = await axios.get(`${canvasUrl}/api/v1/courses/${courseId}/pages/${pageUrl}`, {
            headers: { 'Authorization': `Bearer ${apiToken}` },
            timeout: 10000
        });
        return response.data;
    } catch (err) {
        return null;
    }
}
async function fetchCanvasAssignments(canvasUrl, apiToken) {
    const cacheKey = `assignments-${canvasUrl}`;
    
    if (canvasCache.has(cacheKey)) {
        const cached = canvasCache.get(cacheKey);
        if (Date.now() - cached.timestamp < CACHE_TTL) {
            console.log('✅ Using cached assignments');
            return cached.data;
        }
    }
    
    try {
        const courses = await fetchAllCanvasCourses(canvasUrl, apiToken);
        if (!courses) return [];
        
        let allAssignments = [];
        
        for (const course of courses.slice(0, 10)) {
            try {
                const response = await axios.get(`${canvasUrl}/api/v1/courses/${course.id}/assignments`, {
                    headers: { 'Authorization': `Bearer ${apiToken}` },
                    params: { 
                        per_page: 50,
                        order_by: 'due_at'
                    },
                    timeout: 10000
                });
                
                const assignments = response.data
                    .filter(a => a.due_at)
                    .map(a => ({
                        id: a.id,
                        name: a.name,
                        courseName: course.name,
                        dueAt: a.due_at,
                        htmlUrl: a.html_url,
                        submissionTypes: a.submission_types,
                        pointsPossible: a.points_possible
                    }));
                
                allAssignments.push(...assignments);
            } catch (err) {
                console.error(`Failed to fetch assignments for ${course.name}:`, err.message);
            }
        }
        
        // Sort by due date
        allAssignments.sort((a, b) => new Date(a.dueAt) - new Date(b.dueAt));
        
        canvasCache.set(cacheKey, {
            data: allAssignments,
            timestamp: Date.now()
        });
        
        return allAssignments;
    } catch (err) {
        console.error('Canvas assignments error:', err.message);
        return [];
    }
}

function formatAssignmentsList(assignments, filter = 'upcoming') {
    const now = DateTime.now().setZone('Australia/Sydney');
    const weekFromNow = now.plus({ days: 7 });
    
    let filtered = assignments;
    
    if (filter === 'upcoming') {
        filtered = assignments.filter(a => {
            const due = DateTime.fromISO(a.dueAt).setZone('Australia/Sydney');
            return due > now && due <= weekFromNow;
        });
    } else if (filter === 'overdue') {
        filtered = assignments.filter(a => {
            const due = DateTime.fromISO(a.dueAt).setZone('Australia/Sydney');
            return due < now;
        });
    } else if (filter === 'all') {
        filtered = assignments.filter(a => {
            const due = DateTime.fromISO(a.dueAt).setZone('Australia/Sydney');
            return due > now;
        });
    }
    
    if (filtered.length === 0) {
        return `📋 No ${filter} assignments found.`;
    }
    
    let response = `📋 <strong>${filter.charAt(0).toUpperCase() + filter.slice(1)} Assignments:</strong><br><br>`;
    
    filtered.slice(0, 20).forEach(assignment => {
        const dueDate = DateTime.fromISO(assignment.dueAt).setZone('Australia/Sydney');
        const daysUntil = Math.floor(dueDate.diff(now, 'days').days);
        
        let urgencyColor = '#4caf50';
        if (daysUntil < 0) urgencyColor = '#f44336';
        else if (daysUntil <= 2) urgencyColor = '#ff9800';
        else if (daysUntil <= 5) urgencyColor = '#ffc107';
        
        response += `<div style="background: #f5f5f5; padding: 12px; border-left: 4px solid ${urgencyColor}; border-radius: 5px; margin-bottom: 10px;">`;
        response += `<strong>${escapeHtml(assignment.name)}</strong><br>`;
        response += `<span style="color: #666; font-size: 13px;">📚 ${escapeHtml(assignment.courseName)}</span><br>`;
        response += `<span style="color: ${urgencyColor}; font-weight: bold;">📅 Due: ${dueDate.toFormat('MMM dd, yyyy h:mm a')}</span>`;
        
        if (daysUntil >= 0) {
            response += ` <span style="color: #999;">(${daysUntil === 0 ? 'Today' : daysUntil === 1 ? 'Tomorrow' : `in ${daysUntil} days`})</span>`;
        } else {
            response += ` <span style="color: #f44336; font-weight: bold;">(${Math.abs(daysUntil)} days overdue)</span>`;
        }
        
        if (assignment.pointsPossible) {
            response += `<br><span style="color: #666; font-size: 12px;">💯 ${assignment.pointsPossible} points</span>`;
        }
        
        response += `<br><a href="${assignment.htmlUrl}" target="_blank" style="color: #1976d2; font-size: 12px; text-decoration: none;">View on Canvas →</a>`;
        response += `</div>`;
    });
    
    return response;
}
async function findCanvasContent(canvasUrl, apiToken, courseName, weekNumber = null) {
    const cacheKey = `content-${courseName}-${weekNumber}`;
    
    if (canvasCache.has(cacheKey)) {
        const cached = canvasCache.get(cacheKey);
        if (Date.now() - cached.timestamp < CACHE_TTL) {
            console.log('✅ Using cached content');
            return cached.data;
        }
    }
    
    try {
        const courses = await fetchAllCanvasCourses(canvasUrl, apiToken);
        if (!courses) return { error: 'Could not fetch courses' };

        const searchWords = courseName.toLowerCase().split(/\s+/).filter(w => w.length > 2);
        const course = courses.find(c => {
            if (!c.name) return false;
            const cName = c.name.toLowerCase();
            if (cName.includes(courseName.toLowerCase())) return true;
            return searchWords.some(word => cName.includes(word));
        });

        if (!course) {
            let courseList = courses.slice(0, 10).map(c => `• ${c.name}`).join('<br>');
            return { 
                error: `Course "${courseName}" not found.<br><br><strong>Your courses:</strong><br>${courseList}` 
            };
        }

        const modules = await fetchCanvasModules(canvasUrl, apiToken, course.id);
        if (!modules) return { error: 'Could not fetch modules' };

        let targetModules = modules;
        if (weekNumber !== null) {
            targetModules = modules.filter(m => {
                const name = m.name.toLowerCase();
                return name.includes(`week ${weekNumber}`) || 
                       name.includes(`week${weekNumber}`) ||
                       name.includes(`module ${weekNumber}`) ||
                       name.match(new RegExp(`\\b${weekNumber}\\b`));
            });
        }

        if (targetModules.length === 0) {
            return { error: `No modules found for Week ${weekNumber}` };
        }

        const content = {
            courseName: course.name,
            modules: []
        };

        for (const module of targetModules.slice(0, 3)) {
            const moduleData = { name: module.name, items: [] };
            const items = await fetchCanvasModuleItems(canvasUrl, apiToken, course.id, module.id);
            
            if (items) {
                for (const item of items.slice(0, 10)) {
                    const itemData = {
                        title: item.title,
                        type: item.type,
                        content: ''
                    };

                    try {
                        if (item.type === 'Page' && item.page_url) {
                            const page = await fetchCanvasPage(canvasUrl, apiToken, course.id, item.page_url);
                            if (page && page.body) {
                                itemData.content = page.body.replace(/<[^>]*>/g, ' ').replace(/\s+/g, ' ').trim();
                            }
                        }
                    } catch (itemErr) {
                        itemData.content = 'Content available on Canvas';
                    }

                    moduleData.items.push(itemData);
                }
            }

            content.modules.push(moduleData);
        }

        canvasCache.set(cacheKey, {
            data: content,
            timestamp: Date.now()
        });

        return content;
    } catch (err) {
        console.error('Canvas error:', err.message);
        if (err.code === 'ECONNABORTED' || err.message.includes('timeout')) {
            return { error: 'Canvas is taking too long. Please try again.' };
        }
        if (canvasCache.has(cacheKey)) {
            console.warn('⚠️ Using stale cache due to error');
            return { ...canvasCache.get(cacheKey).data, warning: 'Using cached data (Canvas unavailable)' };
        }
        return { error: 'Unable to connect to Canvas.' };
    }
}

function formatCanvasResponse(canvasContent, weekNumber) {
    let response = `🎨 <strong>${escapeHtml(canvasContent.courseName)}</strong>`;
    if (weekNumber) response += ` - Week ${weekNumber}`;
    response += ':<br><br>';
    
    if (canvasContent.warning) {
        response += `<div style="background:#fff3e0; padding:10px; border-radius:5px; margin-bottom:15px;">⚠️ ${canvasContent.warning}</div>`;
    }
    
    for (const module of canvasContent.modules) {
        response += `<div style="background: #f0f0f0; padding: 15px; border-radius: 8px; margin-bottom: 15px;">`;
        response += `<strong style="color: #614caf;">📚 ${escapeHtml(module.name)}</strong><br><br>`;
        
        if (module.items.length > 0) {
            let allContent = module.items
                .filter(item => item.content && item.content.length > 20)
                .map(item => item.title + '. ' + item.content)
                .join(' ');
            
            if (allContent) {
                response += `<div style="background: white; padding: 15px; border-radius: 5px; margin-bottom:10px;">`;
                response += `<strong>📝 Learning Summary:</strong><br><br>`;
                response += `<div style="line-height: 1.8;">${generateEnhancedSummary(allContent, 2500)}</div>`;
                response += `</div>`;
            }
            
            response += `<strong>📋 Contents:</strong><br><ul style="margin:8px 0; padding-left:20px;">`;
            for (const item of module.items) {
                response += `<li>${escapeHtml(item.title)} <span style="color:#999; font-size:11px;">(${item.type})</span></li>`;
            }
            response += '</ul>';
        }
        
        response += `</div>`;
    }
    
    return response;
}

app.get('/', (req, res) => {
    if (req.session.username) return res.redirect('/chat');
    res.sendFile(path.resolve(__dirname, 'learn.html')); 
});

app.post('/login', loginLimiter, async (req, res) => {
    try {
        const { username, password, mfaToken } = req.body;

        if (!isValidUsername(username)) {
            return res.send(`
                <div style="text-align:center; padding:40px;">
                    <h2 style="color:#d32f2f;">❌ Invalid Username</h2>
                    <p>Use 3-30 alphanumeric characters</p>
                    <a href="/" style="color:#614caf;">← Back to login</a>
                </div>
            `);}

        if (!isValidPassword(password)) {
            return res.send(`
                <div style="text-align:center; padding:40px;">
                    <h2 style="color:#d32f2f;">❌ Invalid Password</h2>
                    <p>Use 8-128 characters</p>
                    <a href="/" style="color:#614caf;">← Back to login</a>
                </div>
            `);
        }

        const users = await loadUsers();

        if (users[username]) {
            const match = await bcrypt.compare(password, users[username].hashedPassword);
            if (!match) {
                return res.send(`
                    <div style="text-align:center; padding:40px;">
                        <h2 style="color:#d32f2f;">❌ Invalid Credentials</h2>
                        <a href="/" style="color:#614caf;">← Try again</a>
                    </div>
                `);
            }
            
            if (users[username].mfaSecret) {
                if (!mfaToken) {
                    return res.send(`
                        <!DOCTYPE html>
                        <html>
                        <head>
                            <title>MFA Required</title>
                            <style>
                                body { font-family: Arial; background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); min-height: 100vh; display: flex; justify-content: center; align-items: center; }
                                .container { background: white; padding: 40px; border-radius: 15px; box-shadow: 0 10px 40px rgba(0,0,0,0.2); max-width: 400px; }
                                h1 { color: #614caf; text-align: center; }
                                input { width: 100%; padding: 12px; border: 2px solid #ddd; border-radius: 8px; font-size: 18px; text-align: center; margin: 20px 0; }
                                button { width: 100%; padding: 14px; background: #614caf; color: white; border: none; border-radius: 8px; font-size: 16px; font-weight: bold; cursor: pointer; }
                                button:hover { background: #4e3d8f; }
                            </style>
                        </head>
                        <body>
                            <div class="container">
                                <h1>🔐 Two-Factor Authentication</h1>
                                <p style="text-align:center; color:#666;">Enter the 6-digit code from your authenticator app</p>
                                <form method="POST" action="/login">
                                    <input type="hidden" name="username" value="${escapeHtml(username)}">
                                    <input type="hidden" name="password" value="${escapeHtml(password)}">
                                    <input type="text" name="mfaToken" placeholder="000000" maxlength="6" pattern="[0-9]{6}" required autofocus>
                                    <button type="submit">Verify & Login</button>
                                </form>
                            </div>
                        </body>
                        </html>
                    `);
                }
                
                const verified = speakeasy.totp.verify({
                    secret: users[username].mfaSecret,
                    encoding: 'base32',
                    token: mfaToken,
                    window: 2
                });
                
                if (!verified) {
                    return res.send(`
                        <div style="text-align:center; padding:40px;">
                            <h2 style="color:#d32f2f;">❌ Invalid MFA Code</h2>
                            <p>The code you entered is incorrect or expired.</p>
                            <a href="/" style="color:#614caf;">← Try again</a>
                        </div>
                    `);
                }
            }
            
            req.session.username = username;
            req.session.chatHistory = [];
            
            if (users[username].encryptedCanvasToken) {
                try {
                    const decryptedToken = decryptToken(users[username].encryptedCanvasToken);
                    req.session.canvasToken = decryptedToken;
                } catch (err) {
                    console.error('Token decryption failed:', err);
                }
            }
            
            req.session.save(() => res.redirect('/chat'));
        } else {
            console.log('Creating new user:', username);
            const hashedPassword = await bcrypt.hash(password, 12);
            await saveUser(username, hashedPassword);
            req.session.username = username;
            req.session.chatHistory = [];
            req.session.save(() => res.redirect('/chat'));
        }
    } catch (err) {
        console.error('Login error:', err);
        res.send(`
            <div style="text-align:center; padding:40px;">
                <h2 style="color:#d32f2f;">❌ Error</h2>
                <p>An error occurred. Please try again.</p>
                <a href="/" style="color:#614caf;">← Back to login</a>
            </div>
        `);
    }
});

app.get('/setup-mfa', async (req, res) => {
    if (!req.session.username) return res.redirect('/');
    
    const users = await loadUsers();
    if (users[req.session.username].mfaSecret) {
        return res.send(`
            <div style="text-align:center; padding:40px;">
                <h1>✅ MFA Already Enabled!</h1>
                <p>Two-factor authentication is active on your account.</p>
                <a href="/chat" style="color:#614caf;">← Back to chat</a>
            </div>
        `);
    }
    
    const secret = speakeasy.generateSecret({
        name: `Unimate (${req.session.username})`
    });
    
    req.session.tempMfaSecret = secret.base32;
    
    qrcode.toDataURL(secret.otpauth_url, (err, dataUrl) => {
        if (err) return res.send('Error generating QR code');
        
        res.send(`
            <!DOCTYPE html>
            <html>
            <head>
                <title>Setup MFA - Unimate</title>
                <style>
                    body { font-family: Arial; background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); min-height: 100vh; display: flex; justify-content: center; align-items: center; padding: 20px; }
                    .container { background: white; padding: 40px; border-radius: 15px; box-shadow: 0 10px 40px rgba(0,0,0,0.2); max-width: 500px; }
                    h1 { color: #614caf; text-align: center; margin-bottom: 20px; }
                    .steps { background: #f0f0f0; padding: 20px; border-radius: 10px; margin: 20px 0; }
                    .steps ol { margin-left: 20px; }
                    .steps li { margin: 10px 0; line-height: 1.6; }
                    img { display: block; margin: 20px auto; max-width: 250px; border: 2px solid #ddd; padding: 10px; border-radius: 10px; background: white; }
                    .secret-code { background: #fff3cd; padding: 15px; border-radius: 8px; text-align: center; margin: 20px 0; word-break: break-all; font-family: monospace; font-size: 14px; }
                    input { width: 100%; padding: 12px; border: 2px solid #ddd; border-radius: 8px; font-size: 18px; text-align: center; margin: 20px 0; box-sizing: border-box; }
                    button { width: 100%; padding: 14px; background: #614caf; color: white; border: none; border-radius: 8px; font-size: 16px; font-weight: bold; cursor: pointer; }
                    button:hover { background: #4e3d8f; }
                    .back-link { display: block; text-align: center; margin-top: 20px; color: #614caf; text-decoration: none; }
                </style>
            </head>
            <body>
                <div class="container">
                    <h1>🔐 Setup Two-Factor Authentication</h1>
                    
                    <div class="steps">
                        <strong>Setup Instructions:</strong>
                        <ol>
                            <li>Install <strong>Google Authenticator</strong> or <strong>Authy</strong> on your phone</li>
                            <li>Scan the QR code below with the app</li>
                            <li>Enter the 6-digit code to verify</li>
                        </ol>
                    </div>
                    
                    <img src="${dataUrl}" alt="QR Code">
                    
                    <p style="text-align:center; color:#666; margin-bottom:10px;">Can't scan? Enter this code manually:</p>
                    <div class="secret-code">${secret.base32}</div>
                    
                    <form method="POST" action="/verify-mfa">
                        <input type="text" name="token" placeholder="000000" maxlength="6" pattern="[0-9]{6}" required autofocus>
                        <button type="submit">✅ Verify & Enable MFA</button>
                    </form>
                    
                    <a href="/chat" class="back-link">← Skip for now</a>
                </div>
            </body>
            </html>
        `);
    });
});

app.post('/verify-mfa', async (req, res) => {
    if (!req.session.username || !req.session.tempMfaSecret) {
        return res.redirect('/');
    }
    
    const { token } = req.body;
    
    const verified = speakeasy.totp.verify({
        secret: req.session.tempMfaSecret,
        encoding: 'base32',
        token: token,
        window: 2
    });
    
    if (verified) {
        const users = await loadUsers();
        await saveUser(
            req.session.username, 
            users[req.session.username].hashedPassword,
            req.session.tempMfaSecret,
            users[req.session.username].encryptedCanvasToken
        );
        delete req.session.tempMfaSecret;
        res.send(`
            <div style="text-align:center; padding:40px;">
                <h1 style="color:#4caf50;">✅ MFA Enabled Successfully!</h1>
                <p>Two-factor authentication is now active on your account.</p>
                <p>You'll need your authenticator app to login from now on.</p>
                <a href="/chat" style="display:inline-block; margin-top:20px; padding:12px 24px; background:#614caf; color:white; text-decoration:none; border-radius:8px;">Back to Chat</a>
            </div>
        `);
    } else {
        res.send(`
            <div style="text-align:center; padding:40px;">
                <h2 style="color:#d32f2f;">❌ Invalid Code</h2>
                <p>The code you entered is incorrect. Please try again.</p>
                <a href="/setup-mfa" style="color:#614caf;">← Try again</a>
            </div>
        `);
    }
});

app.get('/chat', (req, res) => {
    if (!req.session.username) return res.redirect('/');
    const username = escapeHtml(req.session.username);
    
    res.send(`
    <!DOCTYPE html>
    <html>
    <head>
        <meta charset="UTF-8">
        <title>Unimate - ${username}</title>
        <style>
            * { margin: 0; padding: 0; box-sizing: border-box; }
            body { font-family: Arial; background: #f0f0f0; height: 100vh; display: flex; flex-direction: column; }
            .header { background: white; padding: 20px; box-shadow: 0 2px 5px rgba(0,0,0,0.1); display: flex; justify-content: space-between; align-items: center; }
            h1 { font-size: 32px; color: #614caf; }
            .header-links { display: flex; gap: 15px; align-items: center; }
            .mfa-link { color: #614caf; text-decoration: none; font-weight: bold; }
            .logout { color: #614caf; text-decoration: none; font-weight: bold; padding: 10px 20px; border: 2px solid #614caf; border-radius: 5px; transition: all 0.3s; }
            .logout:hover { background: #614caf; color: white; }
            .chat-container { flex: 1; overflow-y: auto; padding: 20px; padding-bottom: 120px; }
            .welcome-card { background: white; padding: 30px; border-radius: 10px; text-align: center; box-shadow: 0 2px 5px rgba(0,0,0,0.1); margin-bottom: 20px; }
            .welcome-card h2 { color: #614caf; margin-bottom: 10px; }
            .canvas-setup { background: white; padding: 20px; border-radius: 10px; box-shadow: 0 2px 5px rgba(0,0,0,0.1); margin-bottom: 20px; }
            .canvas-setup h3 { color: #614caf; margin-bottom: 15px; }
            .canvas-form { display: flex; flex-direction: column; gap: 10px; }
            .canvas-form input { padding: 12px; border: 2px solid #ddd; border-radius: 5px; font-size: 14px; }
            .canvas-btn { background: #614caf; color: white; border: none; padding: 12px; border-radius: 5px; cursor: pointer; font-weight: bold; transition: all 0.3s; }
            .canvas-btn:hover { background: #4e3d8f; }
            .canvas-status { margin-top: 10px; padding: 10px; border-radius: 5px; font-size: 14px; }
            .canvas-status.connected { background: #e8f5e9; color: #388e3c; }
            .canvas-status.disconnected { background: #fff3e0; color: #f57c00; }
            .message { margin-bottom: 15px; display: flex; flex-direction: column; }
            .message.user { align-items: flex-end; }
            .message.bot { align-items: flex-start; }
            .message-bubble { max-width: 70%; padding: 12px 18px; border-radius: 18px; word-wrap: break-word; line-height: 1.6; }
            .message.user .message-bubble { background: #614caf; color: white; }
            .message.bot .message-bubble { background: white; color: #333; box-shadow: 0 1px 2px rgba(0,0,0,0.1); }
            .message-label { font-size: 12px; color: #666; margin-bottom: 5px; padding: 0 10px; }
            .input-area { position: fixed; bottom: 0; left: 0; right: 0; background: #614caf; padding: 20px; box-shadow: 0 -2px 10px rgba(0,0,0,0.1); }
            .file-preview { background: #e3f2fd; padding: 10px; border-radius: 5px; margin-bottom: 10px; display: none; align-items: center; gap: 10px; max-width: 1200px; margin-left: auto; margin-right: auto; }
            .file-preview.show { display: flex; }
            .file-preview-text { flex: 1; color: #1976d2; font-size: 14px; }
            .remove-file { background: #f44336; color: white; border: none; padding: 5px 10px; border-radius: 3px; cursor: pointer; font-size: 12px; }
            .input-form { max-width: 1200px; margin: 0 auto; display: flex; gap: 10px; }
            .file-upload-btn { background: white; color: #614caf; border: none; padding: 15px; border-radius: 50%; cursor: pointer; font-size: 20px; width: 50px; height: 50px; display: flex; align-items: center; justify-content: center; transition: all 0.3s; }
            .file-upload-btn:hover { transform: scale(1.1); }
            .message-input { flex: 1; padding: 15px 20px; border: none; border-radius: 25px; font-size: 16px; outline: none; }
            .send-btn { background: white; color: #614caf; border: none; padding: 15px 30px; border-radius: 25px; cursor: pointer; font-weight: bold; font-size: 16px; transition: all 0.3s; }
            .send-btn:hover { background: #f0f0f0; transform: scale(1.05); }
            .send-btn:disabled { opacity: 0.5; cursor: not-allowed; transform: scale(1); }
        </style>
    </head>
    <body>
        <div class="header">
            <h1>🎓 Unimate</h1>
            <div class="header-links">
                <a href="/setup-mfa" class="mfa-link">🔐 Setup MFA</a>
                <a href="/logout" class="logout">Logout</a>
            </div>
        </div>
        
        <div class="chat-container" id="chatContainer">
            <div class="welcome-card">
                <h2>Welcome back, ${username}! 👋</h2>
                <p>Connect Canvas, upload files, or paste your calendar link!</p>
            </div>
            
            <div class="canvas-setup">
                <h3>🎨 Connect to Canvas</h3>
                <form class="canvas-form" id="canvasForm">
                    <input type="url" id="canvasUrl" placeholder="Canvas URL (e.g., https://canvas.instructure.com)" required>
                    <input type="password" id="canvasToken" placeholder="Canvas API Token (Settings → New Access Token)" required>
                    <button type="submit" class="canvas-btn">Connect Canvas</button>
                </form>
                <div class="canvas-status disconnected" id="canvasStatus">Not connected to Canvas</div>
            </div>
        </div>
        
        <div class="input-area">
            <div class="file-preview" id="filePreview">
                <span class="file-preview-text" id="filePreviewText"></span>
                <button class="remove-file" id="removeFile">✕ Remove</button>
            </div>
            <form class="input-form" id="chatForm">
                <input type="file" id="fileInput" accept=".pdf,.doc,.docx,.txt" style="display: none;">
                <button type="button" class="file-upload-btn" id="fileUploadBtn" title="Upload file">📎</button>
                <input type="text" id="messageInput" class="message-input" placeholder="Type message or ask about your courses..." maxlength="500" autocomplete="off">
                <button type="submit" class="send-btn" id="sendBtn">Send</button>
            </form>
        </div>
        
        <script>
            const chatContainer = document.getElementById('chatContainer');
            const chatForm = document.getElementById('chatForm');
            const messageInput = document.getElementById('messageInput');
            const sendBtn = document.getElementById('sendBtn');
            const fileInput = document.getElementById('fileInput');
            const fileUploadBtn = document.getElementById('fileUploadBtn');
            const filePreview = document.getElementById('filePreview');
            const filePreviewText = document.getElementById('filePreviewText');
            const removeFileBtn = document.getElementById('removeFile');
            const canvasForm = document.getElementById('canvasForm');
            const canvasStatus = document.getElementById('canvasStatus');
            
            let selectedFile = null;
            
            checkCanvasStatus();
            
            async function checkCanvasStatus() {
                try {
                    const response = await fetch('/api/canvas-status');
                    const data = await response.json();
                    if (data.connected) {
                        canvasStatus.textContent = '✅ Connected to Canvas';
                        canvasStatus.className = 'canvas-status connected';
                    }
                } catch (err) {
                    console.error('Canvas status check failed:', err);
                }
            }
            
            canvasForm.addEventListener('submit', async (e) => {
                e.preventDefault();
                const canvasUrl = document.getElementById('canvasUrl').value.trim();
                const canvasToken = document.getElementById('canvasToken').value.trim();
                canvasStatus.textContent = '⏳ Connecting to Canvas...';
                canvasStatus.className = 'canvas-status';
                try {
                    const response = await fetch('/api/connect-canvas', {
                        method: 'POST',
                        headers: { 'Content-Type': 'application/json' },
                        body: JSON.stringify({ canvasUrl, canvasToken })
                    });
                    const data = await response.json();
                    if (response.ok) {
                        canvasStatus.textContent = '✅ Connected - ' + data.coursesCount + ' courses found!';
                        canvasStatus.className = 'canvas-status connected';
                        addMessage(data.message, false);
                        document.getElementById('canvasToken').value = '';
                    } else {
                        canvasStatus.textContent = '❌ ' + data.error;
                        canvasStatus.className = 'canvas-status disconnected';
                    }
                } catch (err) {
                    canvasStatus.textContent = '❌ Connection failed';
                    canvasStatus.className = 'canvas-status disconnected';
                }
            });
            
            fileUploadBtn.addEventListener('click', () => fileInput.click());
            
            fileInput.addEventListener('change', (e) => {
                const file = e.target.files[0];
                if (file) {
                    selectedFile = file;
                    filePreviewText.textContent = '📄 ' + file.name;
                    filePreview.classList.add('show');
                }
            });
            
            removeFileBtn.addEventListener('click', () => {
                selectedFile = null;
                fileInput.value = '';
                filePreview.classList.remove('show');
            });
            
            function scrollToBottom() {
                chatContainer.scrollTop = chatContainer.scrollHeight;
            }
            
            function addMessage(text, isUser) {
                const messageDiv = document.createElement('div');
                messageDiv.className = 'message ' + (isUser ? 'user' : 'bot');
                const label = document.createElement('div');
                label.className = 'message-label';
                label.textContent = isUser ? 'You' : 'Unimate';
                const bubble = document.createElement('div');
                bubble.className = 'message-bubble';
                bubble.innerHTML = text;
                messageDiv.appendChild(label);
                messageDiv.appendChild(bubble);
                chatContainer.appendChild(messageDiv);
                scrollToBottom();
            }
            
            chatForm.addEventListener('submit', async (e) => {
                e.preventDefault();
                const message = messageInput.value.trim();
                
                if (selectedFile) {
                    const formData = new FormData();
                    formData.append('file', selectedFile);
                    if (message) formData.append('message', message);
                    addMessage('📎 ' + selectedFile.name + (message ? '<br>' + message : ''), true);
                    messageInput.value = '';
                    sendBtn.disabled = true;
                    sendBtn.textContent = 'Uploading...';
                    try {
                        const response = await fetch('/api/upload-chat', { method: 'POST', body: formData });
                        const data = await response.json();
                        addMessage(data.response, false);
                        selectedFile = null;
                        fileInput.value = '';
                        filePreview.classList.remove('show');
                    } catch (error) {
                        addMessage('Sorry, upload failed.', false);
                    }
                    sendBtn.disabled = false;
                    sendBtn.textContent = 'Send';
                    messageInput.focus();
                    return;
                }
                
                if (!message) return;
                addMessage(message, true);
                messageInput.value = '';
                sendBtn.disabled = true;
                sendBtn.textContent = 'Sending...';
                try {
                    const response = await fetch('/api/chat', {
                        method: 'POST',
                        headers: { 'Content-Type': 'application/json' },
                        body: JSON.stringify({ message })
                    });
                    const data = await response.json();
                    addMessage(data.response, false);
                } catch (error) {
                    addMessage('Sorry, something went wrong.', false);
                }
                sendBtn.disabled = false;
                sendBtn.textContent = 'Send';
                messageInput.focus();
            });
            
            messageInput.focus();
            scrollToBottom();
        </script>
    </body>
    </html>
    `);
});

app.post('/api/connect-canvas', async (req, res) => {
    if (!req.session.username) return res.status(401).json({ error: 'Please login first.' });
    try {
        const { canvasUrl, canvasToken } = req.body;
        if (!canvasUrl || !canvasToken) return res.status(400).json({ error: 'Canvas URL and token required.' });
        
        const courses = await fetchAllCanvasCourses(canvasUrl, canvasToken);
        if (!courses) return res.status(400).json({ error: 'Failed to connect. Check URL and token.' });
        
        const encryptedToken = encryptToken(canvasToken);
        await updateUserCanvasToken(req.session.username, encryptedToken);
        
        req.session.canvasUrl = canvasUrl;
        req.session.canvasToken = canvasToken;
        req.session.canvasCourses = courses;
        
        res.json({ message: `✅ Connected! Found ${courses.length} courses.`, coursesCount: courses.length });
    } catch (err) {
        console.error('Canvas error:', err);
        res.status(500).json({ error: 'Failed to connect to Canvas.' });
    }
});

app.get('/api/canvas-status', (req, res) => {
    if (!req.session.username) return res.status(401).json({ connected: false });
    res.json({ connected: !!(req.session.canvasUrl && req.session.canvasToken) });
});

app.post('/api/upload-chat', upload.single('file'), async (req, res) => {
    if (!req.session.username) return res.status(401).json({ response: 'Please login first.' });
    try {
        const file = req.file;
        const message = req.body.message || '';
        if (!file) return res.status(400).json({ response: '❌ No file uploaded.' });
        
        const text = await extractTextFromFile(file.path);
        if (!text) return res.status(400).json({ response: '❌ Could not read file.' });
        
        if (!req.session.uploadedFiles) req.session.uploadedFiles = [];
        
        let weekNumber = null;
        const filenameWeekMatch = file.originalname.match(/week\s*(\d+)|module\s*(\d+)|w(\d+)|m(\d+)/i);
        const messageWeekMatch = message.match(/week\s*(\d+)|module\s*(\d+)/i);
        if (messageWeekMatch) weekNumber = parseInt(messageWeekMatch[1] || messageWeekMatch[2]);
        else if (filenameWeekMatch) weekNumber = parseInt(filenameWeekMatch[1] || filenameWeekMatch[2] || filenameWeekMatch[3] || filenameWeekMatch[4]);
        
        const fileData = {
            id: Date.now().toString(),
            filename: file.originalname,
            filepath: file.path,
            textContent: text,
            weekNumber: weekNumber,
            uploadedAt: new Date().toISOString()
        };
        
        req.session.uploadedFiles.push(fileData);
        req.session.lastUploadedFile = fileData;
        
        let responseMsg = `✅ File uploaded: <strong>${escapeHtml(file.originalname)}</strong>`;
        if (weekNumber) responseMsg += `<br>📅 Detected: Week ${weekNumber}`;
        
        if (message.toLowerCase().includes('summar')) {
            const summary = generateEnhancedSummary(text);
            return res.json({ response: responseMsg + `<br><br>📄 <strong>Learning Summary:</strong><br><br><div style="background: #f9f9f9; padding: 15px; border-radius: 8px; line-height: 1.6;">${summary}</div>` });
        }
        
        responseMsg += `<br><br>Ask: `;
        if (weekNumber) responseMsg += `"week ${weekNumber} summary"`;
        else responseMsg += `"give me a summary"`;
        
        res.json({ response: responseMsg });
    } catch (err) {
        console.error('Upload error:', err);
        res.status(500).json({ response: '❌ Failed to upload.' });
    }
});

app.post('/api/chat', calendarLimiter, async (req, res) => {
    if (!req.session.username) return res.status(401).json({ response: 'Please login first.' });
    try {
        const raw = (req.body.message || '').trim();
        const msg = raw.toLowerCase();
        if (!req.session.chatHistory) req.session.chatHistory = [];
        
        const weekMatch = msg.match(/week\s*(\d+)|module\s*(\d+)/i);
        const hasWeekNumber = weekMatch !== null;
        
        const datePatterns = [
            /(\d{1,2})\s*(jan|feb|mar|apr|may|jun|jul|aug|sep|oct|nov|dec)[a-z]*(?:\s+(\d{4}))?/i,
            /(\d{1,2})\/(\d{1,2})\/(\d{4})/,
            /(\d{4})-(\d{1,2})-(\d{1,2})/
        ];

        let specificDate = null;

        const dayOfWeekMatch = msg.match(/\b(mon|monday|tue|tues|tuesday|wed|wednesday|thu|thurs|thursday|fri|friday|sat|saturday|sun|sunday)\b/i);
        if (dayOfWeekMatch) {
            const dayMap = {
                'mon': 1, 'monday': 1,
                'tue': 2, 'tues': 2, 'tuesday': 2,
                'wed': 3, 'wednesday': 3,
                'thu': 4, 'thurs': 4, 'thursday': 4,
                'fri': 5, 'friday': 5,
                'sat': 6, 'saturday': 6,
                'sun': 7, 'sunday': 7
            };
            
            const targetDay = dayMap[dayOfWeekMatch[1].toLowerCase()];
            const today = DateTime.now().setZone('Australia/Sydney');
            const currentDay = today.weekday;
            
            let daysUntil = targetDay - currentDay;
            if (daysUntil < 0) daysUntil += 7;
            if (daysUntil === 0 && !msg.includes('this')) daysUntil = 7;
            
            specificDate = today.plus({ days: daysUntil });
        }

        if (!specificDate) {
            for (const pattern of datePatterns) {
                const match = msg.match(pattern);
                if (match) {
                    try {
                        if (pattern === datePatterns[0]) {
                            const monthMap = {jan:1,feb:2,mar:3,apr:4,may:5,jun:6,jul:7,aug:8,sep:9,oct:10,nov:11,dec:12};
                            const month = monthMap[match[2].toLowerCase().slice(0,3)];
                            const year = match[3] ? parseInt(match[3]) : DateTime.now().year;
                            specificDate = DateTime.fromObject({
                                year: year,
                                month: month,
                                day: parseInt(match[1])
                            }, { zone: 'Australia/Sydney' });
                        } else if (pattern === datePatterns[1]) {
                            specificDate = DateTime.fromObject({
                                year: parseInt(match[3]),
                                month: parseInt(match[1]),
                                day: parseInt(match[2])
                            }, { zone: 'Australia/Sydney' });
                        } else if (pattern === datePatterns[2]) {
                            specificDate = DateTime.fromObject({
                                year: parseInt(match[1]),
                                month: parseInt(match[2]),
                                day: parseInt(match[3])
                            }, { zone: 'Australia/Sydney' });
                        }
                        break;
                    } catch(e) {
                        console.error('Date parsing error:', e);
                    }
                }
            }
        }
        
        if (hasWeekNumber && req.session.uploadedFiles && req.session.uploadedFiles.length > 0) {
            const weekNumber = parseInt(weekMatch[1] || weekMatch[2]);
            const weekFiles = req.session.uploadedFiles.filter(f => f.weekNumber === weekNumber);
            if (weekFiles.length > 0) {
                const file = weekFiles[weekFiles.length - 1];
                const summary = generateEnhancedSummary(file.textContent);
                return res.json({ response: `📄 <strong>Week ${weekNumber}: ${escapeHtml(file.filename)}</strong><br><br><strong>Learning Summary:</strong><br><br><div style="background: #f9f9f9; padding: 15px; border-radius: 8px; line-height: 1.6;">${summary}</div>` });
            }
        }
        
        if (hasWeekNumber && req.session.canvasUrl && req.session.canvasToken) {
            const weekNumber = parseInt(weekMatch[1] || weekMatch[2]);
            let courseName = msg.replace(/week\s*\d+/gi, '').replace(/module\s*\d+/gi, '').replace(/\b(show|give|get|tell|what|whats|is|in|my|me|about|the|a|an|of|for|from|summary|content|learnt|learned|learn)\b/gi, '').trim();
            
            if (!courseName || courseName.length < 2) {
                const courses = req.session.canvasCourses || [];
                if (courses.length > 0) {
                    for (const course of courses.slice(0, 5)) {
                        const canvasContent = await findCanvasContent(req.session.canvasUrl, req.session.canvasToken, course.name, weekNumber);
                        if (canvasContent && canvasContent.modules && canvasContent.modules.length > 0) {
                            return res.json({ response: formatCanvasResponse(canvasContent, weekNumber) });
                        }
                    }
                    return res.json({ response: `🎨 No courses found with Week ${weekNumber}.` });
                }
            } 
            
            else {
                const canvasContent = await findCanvasContent(req.session.canvasUrl, req.session.canvasToken, courseName, weekNumber);
                if (canvasContent && canvasContent.error) {
                    return res.json({ response: `🎨 ${canvasContent.error}` });
                }
                if (canvasContent && canvasContent.modules) {
                    return res.json({ response: formatCanvasResponse(canvasContent, weekNumber) });
                }
            }
        }
        // Check for tasks/assignments queries
const tasksKeywords = ['task', 'assignment', 'deadline', 'due', 'homework'];
const isTaskQuery = tasksKeywords.some(keyword => msg.includes(keyword));

if (isTaskQuery && req.session.canvasUrl && req.session.canvasToken) {
    const assignments = await fetchCanvasAssignments(req.session.canvasUrl, req.session.canvasToken);
    
    let filter = 'upcoming';
    if (msg.includes('overdue') || msg.includes('late') || msg.includes('missed')) {
        filter = 'overdue';
    } else if (msg.includes('all')) {
        filter = 'all';
    }
    
    return res.json({ response: formatAssignmentsList(assignments, filter) });
}


        const summaryKeywords = ['summary', 'summarize', 'what', 'explain', 'tell me about', 'content'];
        const isAskingAboutFile = summaryKeywords.some(keyword => msg.includes(keyword));
        if (isAskingAboutFile && !hasWeekNumber && req.session.lastUploadedFile) {
            const file = req.session.lastUploadedFile;
            const summary = generateEnhancedSummary(file.textContent);
            return res.json({ response: `📄 <strong>${escapeHtml(file.filename)}</strong><br><br><strong>Learning Summary:</strong><br><br><div style="background: #f9f9f9; padding: 15px; border-radius: 8px; line-height: 1.6;">${summary}</div>` });
        }
        
        const urlMatch = raw.match(/https?:\/\/[^\s]+/i);
        if (urlMatch) {
            const url = urlMatch[0];
            if (!isValidCalendarUrl(url)) return res.json({ response: '❌ Invalid calendar URL.' });
            try {
                const events = await fetchIcsEvents(url);
                req.session.icsEvents = events;
                return res.json({ response: `✅ Calendar saved! ${events.length} events found.<br><br>Try: "what classes today?"` });
            } catch (err) {
                return res.json({ response: '❌ Failed to load calendar.' });
            }
        }
        
        const isCalendarQuery = msg.includes("class") || msg.includes("today") || msg.includes("tom") || msg.includes("schedule") || msg.includes("where");
        if (isCalendarQuery && !hasWeekNumber) {
            const events = req.session.icsEvents;
            if (!events) return res.json({ response: '📅 No calendar found. Paste your calendar link!' });
            
            let targetDate = specificDate || DateTime.now().setZone('Australia/Sydney');
            let label = "today";
            
            if (specificDate) {
                label = specificDate.toFormat('MMMM d, yyyy (cccc)');
            } else if (msg.includes("tom")) {
                targetDate = targetDate.plus({ days: 1 });
                label = "tomorrow";
            }
            
            const isLocationQuery = msg.includes("where");
            
            if (isLocationQuery) {
                let className = msg
    .replace(/where|today|tomorrow|class|classes|is|are|my|the|on|at/gi, '')
    .replace(/\b(mon|monday|tue|tues|tuesday|wed|wednesday|thu|thurs|thursday|fri|friday|sat|saturday|sun|sunday)\b/gi, '')
    .replace(/\d{1,2}\s*(jan|feb|mar|apr|may|jun|jul|aug|sep|oct|nov|dec)[a-z]*\s*\d{4}/gi, '')
    .replace(/\d{1,2}\/\d{1,2}\/\d{4}/g, '')
    .replace(/\d{4}-\d{1,2}-\d{1,2}/g, '')
    .replace(/october|november|december|january|february|march|april|may|june|july|august|september/gi, '')
    .replace(/,/g, '')
    .replace(/\d+/g, '')
    .trim();
                
                const matchingClasses = findClassLocation(events, className, 'Australia/Sydney', targetDate);
                
                if (matchingClasses.length === 0) {
                    return res.json({ response: `📍 No classes found ${label}${className ? ` matching "${className}"` : ''}.` });
                }
                
                if (matchingClasses.length === 1) {
                    const cls = matchingClasses[0];
                    let response = `📍 <strong>${cls.name}</strong><br>🕐 Time: ${cls.time}<br>📌 Location: <strong>${cls.location}</strong>`;
                    
                    const userLocation = req.session.userLocation || 'University of Technology Sydney';
                    
                    try {
                        const directions = await getOpenStreetMapDirections(userLocation, cls.location);
                        
                        if (directions) {
                            response += `<br><br><div style="background: #e3f2fd; padding: 15px; border-radius: 8px; margin-top: 10px;">`;
                            response += `<strong style="color: #1976d2;">🗺️ Walking Directions:</strong><br>`;
                            response += `⏱️ ${directions.duration} (${directions.distance})<br><br>`;
                            
                            directions.steps.slice(0, 10).forEach((step, index) => {
                                response += `<div style="margin: 8px 0;"><strong>${index + 1}.</strong> ${escapeHtml(step)}</div>`;
                            });
                            
                            response += `<br><a href="${directions.mapsUrl}" target="_blank" style="display: inline-block; padding: 10px 20px; background: #1976d2; color: white; text-decoration: none; border-radius: 5px; margin-top: 10px;">📍 Open in Maps</a>`;
                            response += `</div>`;
                        } else {
                            const mapsSearchUrl = `https://www.openstreetmap.org/search?query=${encodeURIComponent(cls.location)}`;
                            response += `<br><br><a href="${mapsSearchUrl}" target="_blank" style="color: #1976d2;">📍 View on Map</a>`;
                        }
                    } catch (err) {
                        console.error('Direction error:', err);
                        const mapsSearchUrl = `https://www.openstreetmap.org/search?query=${encodeURIComponent(cls.location)}`;
                        response += `<br><br><a href="${mapsSearchUrl}" target="_blank" style="color: #1976d2;">📍 View on Map</a>`;
                    }
                    
                    return res.json({ response });
                }
                
                let response = `📍 <strong>Class locations ${label}:</strong><br><br>`;
                matchingClasses.forEach(cls => {
                    const mapsSearchUrl = `https://www.openstreetmap.org/search?query=${encodeURIComponent(cls.location)}`;
                    response += `<div style="background: #f5f5f5; padding: 10px; border-radius: 5px; margin-bottom: 10px;">`;
                    response += `<strong>${cls.name}</strong><br>`;
                    response += `🕐 ${cls.time}<br>`;
                    response += `📌 <strong>${cls.location}</strong><br>`;
                    response += `<a href="${mapsSearchUrl}" target="_blank" style="color: #1976d2; font-size: 12px;">📍 Directions</a>`;
                    response += `</div>`;
                });
                return res.json({ response });
            }
            
            const list = eventsForDate(events, 'Australia/Sydney', targetDate);
            
            if (list.length) {
                const eventsList = list.map(e => `<li style="margin:5px 0;">📚 ${e}</li>`).join('');
                return res.json({ response: `📅 <strong>Classes on ${label}:</strong><ul style="list-style:none;padding-left:0;">${eventsList}</ul>` });
            } else {
                return res.json({ response: `📅 No classes on ${label}` });
            }
        }
        
        let helpMessage = `I can help you with:<br><br>`;
        if (req.session.lastUploadedFile) helpMessage += `📄 <strong>Your file:</strong> "${req.session.lastUploadedFile.filename}"<br>• Ask: "give me a summary"<br><br>`;
        if (req.session.canvasUrl) helpMessage += `🎨 <strong>Canvas connected:</strong><br>• "week 2 python"<br>• "what did i learn week 3"<br><br>`;
        if (req.session.canvasUrl) helpMessage += `🎨 <strong>Canvas connected:</strong><br>• "week 2 python"<br>• "what did i learn week 3"<br>• "show my assignments"<br>• "what tasks are due"<br>• "overdue assignments"<br><br>`;
        helpMessage += `📅 <strong>Calendar:</strong><br>• Paste your calendar link<br>• "classes today"<br>• "class on 24 nov 2025"<br><br>`;
        helpMessage += `📍 <strong>Locations:</strong><br>• "where is my class today"<br>• "where is python today"<br>• "where are my classes tomorrow"<br><br>`;
        helpMessage += `💡 Upload files or connect Canvas to get started!`;
        res.json({ response: helpMessage });
    } catch (err) {
        console.error('Chat error:', err);
        res.json({ response: 'Sorry, an error occurred.' });
    }
});

app.get('/logout', (req, res) => {
    req.session.destroy(() => res.redirect('/'));
});

app.use((err, req, res, next) => {
    console.error('Unhandled error:', err);
    res.status(500).json({ response: 'An unexpected error occurred.' });
});

app.listen(PORT, () => {
    console.log(`✅ Server running on http://localhost:${PORT}`);
    console.log(`📦 Sessions stored in files (survives restarts!)`);
    console.log(`🔐 MFA available at /setup-mfa`);
    console.log(`🔒 Canvas tokens encrypted with AES-256`);
    console.log(`⚡ Canvas API responses cached for 5 minutes`);
    console.log(`📚 Enhanced summaries with tasks, concepts & objectives`);
    console.log(`📍 Location feature enabled`);
    if (!process.env.SESSION_SECRET) console.warn('⚠️  Set SESSION_SECRET in production!');
});