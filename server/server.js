import express from 'express';
import cors from 'cors';
import rateLimit from 'express-rate-limit';
import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';

const app = express();
const PORT = process.env.PORT || 3000;
const ADMIN_TOKEN = process.env.ADMIN_TOKEN || '';
const DATA_DIR = process.env.DATA_DIR || path.join(process.cwd(), 'data');
const DATA_FILE = path.join(DATA_DIR, 'keys.json');

fs.mkdirSync(DATA_DIR, { recursive: true });
if (!fs.existsSync(DATA_FILE)) fs.writeFileSync(DATA_FILE, '[]');

app.use(cors({ origin: process.env.CORS_ORIGIN || '*' }));
app.use(express.json({ limit: '32kb' }));
app.use(rateLimit({ windowMs: 60_000, limit: 120, standardHeaders: 'draft-7', legacyHeaders: false }));

function readKeys() {
  try { return JSON.parse(fs.readFileSync(DATA_FILE, 'utf8')); } catch { return []; }
}
function writeKeys(keys) {
  const tmp = DATA_FILE + '.tmp';
  fs.writeFileSync(tmp, JSON.stringify(keys, null, 2));
  fs.renameSync(tmp, DATA_FILE);
}
function hashKey(key) { return crypto.createHash('sha256').update(key).digest('hex'); }
function makeKey(prefix = 'NAGI') {
  const safe = String(prefix).toUpperCase().replace(/[^A-Z0-9]/g, '').slice(0, 12) || 'NAGI';
  const random = crypto.randomBytes(18).toString('base64url').replace(/[-_]/g, '').slice(0, 18).toUpperCase();
  return `${safe}-${random.slice(0,6)}-${random.slice(6,12)}-${random.slice(12,18)}`;
}
function expiryFor(plan) {
  const days = { Daily: 1, Monthly: 30, Yearly: 365, Lifetime: 0 }[plan];
  if (days === undefined) return undefined;
  return days === 0 ? null : Date.now() + days * 86400000;
}
function admin(req, res, next) {
  if (!ADMIN_TOKEN || req.get('authorization') !== `Bearer ${ADMIN_TOKEN}`) return res.status(401).json({ valid:false, message:'Unauthorized' });
  next();
}

app.get('/health', (_req, res) => res.json({ ok:true, service:'NagiHub Key API' }));

app.post('/api/keys/validate', (req, res) => {
  const key = String(req.body?.key || '').trim().toUpperCase();
  const userId = String(req.body?.userId || '').trim();
  if (!key) return res.status(400).json({ valid:false, message:'Key is required' });
  const keys = readKeys();
  const item = keys.find(k => k.hash === hashKey(key));
  if (!item || item.revoked) return res.status(404).json({ valid:false, message:'Invalid or revoked key' });
  if (item.expiresAt !== null && item.expiresAt <= Date.now()) return res.status(410).json({ valid:false, message:'Key expired' });
  if (item.boundUserId && item.boundUserId !== userId) return res.status(403).json({ valid:false, message:'Key is bound to another Roblox account' });
  if (userId && !item.boundUserId) {
    item.boundUserId = userId;
    item.boundAt = Date.now();
    writeKeys(keys);
  }
  return res.json({ valid:true, plan:item.plan, expiresAt:item.expiresAt, boundUserId:item.boundUserId || null, message:'Key accepted' });
});

app.post('/api/admin/keys/generate', admin, (req, res) => {
  const plan = String(req.body?.plan || 'Daily');
  const allowed = ['Daily','Monthly','Yearly','Lifetime'];
  if (!allowed.includes(plan)) return res.status(400).json({ message:'Invalid plan' });
  const count = Math.min(Math.max(Number(req.body?.count || 1), 1), 100);
  const prefix = req.body?.prefix || 'NAGI';
  const note = String(req.body?.note || '').slice(0, 200);
  const keys = readKeys();
  const created = [];
  for (let i=0;i<count;i++) {
    const plain = makeKey(prefix);
    const item = { id: crypto.randomUUID(), hash: hashKey(plain), plan, createdAt: Date.now(), expiresAt: expiryFor(plan), active:true, revoked:false, boundUserId:null, note };
    keys.push(item);
    created.push({ key:plain, plan, expiresAt:item.expiresAt, id:item.id });
  }
  writeKeys(keys);
  res.json({ ok:true, keys:created });
});

app.get('/api/admin/keys', admin, (_req, res) => {
  const items = readKeys().map(({ hash, ...k }) => k);
  res.json({ keys:items });
});

app.post('/api/admin/keys/:id/revoke', admin, (req, res) => {
  const keys = readKeys();
  const item = keys.find(k => k.id === req.params.id);
  if (!item) return res.status(404).json({ message:'Key not found' });
  item.revoked = true;
  item.active = false;
  item.revokedAt = Date.now();
  writeKeys(keys);
  res.json({ ok:true });
});

app.listen(PORT, () => console.log(`NagiHub Key API listening on ${PORT}`));
