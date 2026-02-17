const express = require('express');
const path = require('path');
const cookieParser = require('cookie-parser');
const { createProxyMiddleware } = require('http-proxy-middleware');
const { pool, migrate } = require('./lib/db');
const streams = require('./lib/streams');
const mediamtx = require('./lib/mediamtx-client');
const scaler = require('./lib/jibri-scaler');
const auth = require('./lib/auth');

const app = express();
const PORT = parseInt(process.env.PORT || '3000');
const MEDIAMTX_HLS_URL = process.env.MEDIAMTX_HLS_URL || 'http://localhost:8888';
const MEDIAMTX_RTMP_HOST = process.env.MEDIAMTX_RTMP_HOST || 'jitsi-live-mediamtx';
const PUBLIC_HOST = process.env.PUBLIC_HOST || 'live.overlord.se';
const JITSI_DOMAIN = process.env.JITSI_DOMAIN || 'prat.overlord.se';
const BRANDING_SITE_NAME = process.env.BRANDING_SITE_NAME || 'Overlord Live';
const BRANDING_TAGLINE = process.env.BRANDING_TAGLINE || 'Livestreaming från Jitsi.';
const BRANDING_LOGO_URL = process.env.BRANDING_LOGO_URL || '/logo.svg';
const HLS_LIVE_SYNC_DURATION = parseFloat(process.env.HLS_LIVE_SYNC_DURATION || '3');
const HLS_MAX_LATENCY_DURATION = parseFloat(process.env.HLS_MAX_LATENCY_DURATION || '8');
const HLS_MAX_BUFFER_LENGTH = parseFloat(process.env.HLS_MAX_BUFFER_LENGTH || '6');
const HLS_MAX_MAX_BUFFER_LENGTH = parseFloat(process.env.HLS_MAX_MAX_BUFFER_LENGTH || '15');

// Viewer heartbeat tracking (in-memory)
// Map<streamName, Map<viewerId, lastSeenTimestamp>>
const viewerHeartbeats = new Map();
const VIEWER_TIMEOUT_MS = 60000; // 60s — viewer considered gone if no heartbeat

function getViewerCount(streamName) {
  const viewers = viewerHeartbeats.get(streamName);
  if (!viewers) return 0;
  const now = Date.now();
  let count = 0;
  for (const [id, lastSeen] of viewers) {
    if (now - lastSeen < VIEWER_TIMEOUT_MS) {
      count++;
    } else {
      viewers.delete(id);
    }
  }
  if (viewers.size === 0) viewerHeartbeats.delete(streamName);
  return count;
}

app.use(express.json());
app.use(cookieParser());

// Serve branding.js dynamically from env vars (before static middleware)
app.get('/branding.js', (req, res) => {
  res.type('application/javascript');
  res.send(`window.BRANDING = {
  siteName: ${JSON.stringify(BRANDING_SITE_NAME)},
  tagline: ${JSON.stringify(BRANDING_TAGLINE)},
  logoUrl: ${JSON.stringify(BRANDING_LOGO_URL)},
  jitsiDomain: ${JSON.stringify(JITSI_DOMAIN)},
};

function applyBranding() {
  var b = window.BRANDING;
  var titleEl = document.querySelector('title');
  if (titleEl) {
    var current = titleEl.textContent.trim();
    if (!current || current === b.siteName) {
      titleEl.textContent = b.siteName;
    } else if (current.indexOf(b.siteName) === -1) {
      titleEl.textContent = current + ' - ' + b.siteName;
    }
  }
  var h1 = document.getElementById('site-title');
  if (h1 && !h1.textContent.trim()) h1.textContent = b.siteName;
  var tag = document.getElementById('site-tagline');
  if (tag && !tag.textContent.trim()) tag.textContent = b.tagline;
  var logo = document.getElementById('site-logo');
  if (logo) logo.src = b.logoUrl;
}

window.HLS_CONFIG = {
  liveSyncDuration: ${HLS_LIVE_SYNC_DURATION},
  liveMaxLatencyDuration: ${HLS_MAX_LATENCY_DURATION},
  maxBufferLength: ${HLS_MAX_BUFFER_LENGTH},
  maxMaxBufferLength: ${HLS_MAX_MAX_BUFFER_LENGTH},
};
`);
});

app.use(express.static(path.join(__dirname, 'public')));

// EFOS middleware: extract email and name from client certificate headers on every request
app.use((req, res, next) => {
  req.efosEmail = auth.extractEmailFromPem(req.headers['x-client-cert-pem'])
    || auth.extractEmailFromCertInfo(req.headers['x-client-cert-info'])
    || null;
  req.efosName = auth.extractNameFromPem(req.headers['x-client-cert-pem']) || null;
  next();
});

// HLS reverse proxy to MediaMTX
app.use('/hls', createProxyMiddleware({
  target: MEDIAMTX_HLS_URL,
  changeOrigin: true,
  pathRewrite: { '^/hls': '' },
}));

// Health check
app.get('/api/health', async (req, res) => {
  try {
    await pool.query('SELECT 1');
    res.json({ status: 'ok' });
  } catch (err) {
    res.status(503).json({ status: 'error', message: err.message });
  }
});

// --- Auth endpoints ---

// Get current user info (EFOS detection)
app.get('/api/auth/me', async (req, res) => {
  if (req.efosEmail) {
    const admin = await auth.isAdmin(req.efosEmail);
    return res.json({ email: req.efosEmail, name: req.efosName, isEfos: true, isAdmin: admin });
  }
  res.json({ email: null, name: null, isEfos: false, isAdmin: false });
});

// --- My Streams auth (without EFOS) ---

// Login with email + stream key
app.post('/api/my-streams/login', async (req, res) => {
  const { email, key } = req.body;
  if (!email || !key) {
    return res.status(400).json({ error: 'E-post och stream-nyckel krävs' });
  }

  try {
    const stream = await streams.getStreamByKey(key);
    if (!stream || !stream.owner_email || stream.owner_email.toLowerCase() !== email.toLowerCase()) {
      return res.status(403).json({ error: 'Ogiltig kombination av e-post och stream-nyckel' });
    }

    // Set signed cookie (24h)
    const token = auth.signToken({ email: email.toLowerCase(), exp: Date.now() + 24 * 60 * 60 * 1000 });
    res.cookie('my-streams-token', token, { httpOnly: true, sameSite: 'lax', maxAge: 24 * 60 * 60 * 1000 });
    res.json({ ok: true, email: email.toLowerCase() });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Get my streams (requires EFOS or cookie)
app.get('/api/my-streams', async (req, res) => {
  const email = req.efosEmail || getMyStreamsEmail(req);
  if (!email) {
    return res.status(401).json({ error: 'Ej autentiserad' });
  }

  try {
    const list = await streams.listByOwner(email);
    res.json(list);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

function getMyStreamsEmail(req) {
  const token = req.cookies['my-streams-token'];
  if (!token) return null;
  const payload = auth.verifyToken(token);
  return payload ? payload.email : null;
}

// --- Admin endpoints ---

// Admin login with password
app.post('/api/admin/login', async (req, res) => {
  const { password } = req.body;
  try {
    const valid = await auth.checkAdminPassword(password);
    if (!valid) {
      return res.status(403).json({ error: 'Felaktigt lösenord' });
    }

    const passwordChanged = await auth.isPasswordChanged();
    if (!passwordChanged) {
      // First login with initial password — require password change
      // Give a short-lived token that only allows password change
      const token = auth.signToken({ admin: true, mustChangePassword: true, exp: Date.now() + 10 * 60 * 1000 });
      res.cookie('admin-token', token, { httpOnly: true, sameSite: 'lax', maxAge: 10 * 60 * 1000 });
      return res.json({ ok: true, mustChangePassword: true });
    }

    const token = auth.signToken({ admin: true, exp: Date.now() + 8 * 60 * 60 * 1000 });
    res.cookie('admin-token', token, { httpOnly: true, sameSite: 'lax', maxAge: 8 * 60 * 60 * 1000 });
    res.json({ ok: true });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Change admin password (required on first login)
app.post('/api/admin/change-password', async (req, res) => {
  // Must be logged in as admin (EFOS or cookie)
  if (!await isAdminRequest(req)) {
    return res.status(403).json({ error: 'Åtkomst nekad' });
  }

  const { newPassword } = req.body;
  if (!newPassword || newPassword.length < 8) {
    return res.status(400).json({ error: 'Lösenordet måste vara minst 8 tecken' });
  }

  try {
    await auth.setStoredPassword(newPassword);
    // Issue a full admin token now
    const token = auth.signToken({ admin: true, exp: Date.now() + 8 * 60 * 60 * 1000 });
    res.cookie('admin-token', token, { httpOnly: true, sameSite: 'lax', maxAge: 8 * 60 * 60 * 1000 });
    res.json({ ok: true });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Check admin access
app.get('/api/admin/check', async (req, res) => {
  if (req.efosEmail && await auth.isAdmin(req.efosEmail)) {
    return res.json({ ok: true, authMethod: 'efos' });
  }
  const token = req.cookies['admin-token'];
  if (token) {
    const payload = auth.verifyToken(token);
    if (payload && payload.admin) {
      return res.json({ ok: true, authMethod: 'password' });
    }
  }
  res.status(403).json({ error: 'Åtkomst nekad' });
});

// Admin logout (clear cookie)
app.post('/api/admin/logout', (req, res) => {
  res.clearCookie('admin-token');
  res.json({ ok: true });
});

async function isAdminRequest(req) {
  // EFOS admin
  if (req.efosEmail && await auth.isAdmin(req.efosEmail)) return true;
  // Password-based admin cookie
  const token = req.cookies['admin-token'];
  if (token) {
    const payload = auth.verifyToken(token);
    if (payload && payload.admin) return true;
  }
  return false;
}

// List admins
app.get('/api/admins', async (req, res) => {
  if (!await isAdminRequest(req)) {
    return res.status(403).json({ error: 'Åtkomst nekad' });
  }
  try {
    const list = await auth.getAdmins();
    res.json(list);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Add admin
app.post('/api/admins', async (req, res) => {
  if (!await isAdminRequest(req)) {
    return res.status(403).json({ error: 'Åtkomst nekad' });
  }
  const { email, name } = req.body;
  if (!email) return res.status(400).json({ error: 'E-post krävs' });
  try {
    const admin = await auth.addAdmin(email, name);
    res.status(201).json(admin);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Remove admin
app.delete('/api/admins/:email', async (req, res) => {
  if (!await isAdminRequest(req)) {
    return res.status(403).json({ error: 'Åtkomst nekad' });
  }
  try {
    const removed = await auth.removeAdmin(decodeURIComponent(req.params.email));
    if (!removed) return res.status(404).json({ error: 'Admin hittades inte' });
    res.json({ deleted: true, email: removed.email });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// --- Stream endpoints ---

// Viewer heartbeat (called by viewer.html every 30s)
app.post('/api/streams/:name/viewer-heartbeat', (req, res) => {
  const { viewerId } = req.body;
  if (!viewerId) return res.status(400).json({ error: 'viewerId krävs' });
  const name = req.params.name;
  if (!viewerHeartbeats.has(name)) {
    viewerHeartbeats.set(name, new Map());
  }
  viewerHeartbeats.get(name).set(viewerId, Date.now());
  res.json({ ok: true });
});

// List all streams (with viewer counts)
app.get('/api/streams', async (req, res) => {
  try {
    const list = await streams.listStreams();
    const enriched = list.map(s => ({
      ...s,
      viewers: getViewerCount(s.name),
    }));
    res.json(enriched);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Create stream
app.post('/api/streams', async (req, res) => {
  const { name, email: bodyEmail, ownerName: bodyName, scheduledStart } = req.body;
  if (!name || !/^[a-z0-9-]+$/.test(name)) {
    return res.status(400).json({ error: 'Name must be lowercase alphanumeric with hyphens only' });
  }

  // EFOS email takes priority, then body email
  const ownerEmail = req.efosEmail || bodyEmail || null;
  if (!req.efosEmail && !bodyEmail) {
    return res.status(400).json({ error: 'E-postadress krävs när inget EFOS-kort används' });
  }

  // Owner name: EFOS CN takes priority, then body
  const ownerName = req.efosName || bodyName || null;
  if (!ownerName) {
    return res.status(400).json({ error: 'Namn krävs' });
  }

  // Parse scheduled start time
  let parsedStart = null;
  if (scheduledStart) {
    parsedStart = new Date(scheduledStart);
    if (isNaN(parsedStart.getTime())) {
      return res.status(400).json({ error: 'Ogiltigt datum för planerad start' });
    }
  }

  try {
    const existing = await streams.getStream(name);
    if (existing) {
      return res.status(409).json({ error: 'Stream name already exists' });
    }

    const stream = await streams.createStream(name, ownerEmail, ownerName, parsedStart);

    // Scale up Jibri if stream is starting soon (within 90 min window)
    const count = await streams.countStreamsNeedingJibri();
    await scaler.reconcile(count);

    res.status(201).json({
      name: stream.name,
      key: stream.key,
      rtmpUrl: `rtmp://${MEDIAMTX_RTMP_HOST}:1935/${stream.key}`,
      viewUrl: `https://${PUBLIC_HOST}/live/${stream.name}`,
      hlsUrl: `https://${PUBLIC_HOST}/hls/${stream.key}/`,
      status: stream.status,
      ownerEmail: stream.owner_email,
      ownerName: stream.owner_name,
      scheduledStart: stream.scheduled_start,
    });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Get stream info
app.get('/api/streams/:name', async (req, res) => {
  try {
    const stream = await streams.getStream(req.params.name);
    if (!stream) {
      return res.status(404).json({ error: 'Stream not found' });
    }

    const live = await mediamtx.isStreamLive(stream.key);

    res.json({
      name: stream.name,
      key: stream.key,
      rtmpUrl: `rtmp://${MEDIAMTX_RTMP_HOST}:1935/${stream.key}`,
      viewUrl: `https://${PUBLIC_HOST}/live/${stream.name}`,
      hlsUrl: `https://${PUBLIC_HOST}/hls/${stream.key}/`,
      status: live ? 'live' : stream.status,
      createdAt: stream.created_at,
      ownerName: stream.owner_name,
      scheduledStart: stream.scheduled_start,
      jitsiDomain: JITSI_DOMAIN,
      viewers: getViewerCount(stream.name),
    });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Delete stream (admin or owner)
app.delete('/api/streams/:name', async (req, res) => {
  try {
    const stream = await streams.getStream(req.params.name);
    if (!stream) {
      return res.status(404).json({ error: 'Stream not found' });
    }

    // Check authorization: admin, EFOS owner, or cookie owner
    const isAdm = await isAdminRequest(req);
    const ownerEmail = req.efosEmail || getMyStreamsEmail(req);
    const isOwner = ownerEmail && stream.owner_email && ownerEmail.toLowerCase() === stream.owner_email.toLowerCase();

    if (!isAdm && !isOwner) {
      return res.status(403).json({ error: 'Ingen behörighet att ta bort denna stream' });
    }

    const deleted = await streams.deleteStream(req.params.name);

    // Reconcile Jibri scaling
    const count = await streams.countStreamsNeedingJibri();
    await scaler.reconcile(count);

    res.json({ deleted: true, name: deleted.name });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Page routes (must be before /:name catch-all)
app.get('/start/:name', async (req, res) => {
  const stream = await streams.getStream(req.params.name);
  if (!stream) {
    return res.status(404).send('Stream not found');
  }
  res.sendFile(path.join(__dirname, 'public', 'start.html'));
});

app.get('/order', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'order.html'));
});

app.get('/admin', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'admin.html'));
});

app.get('/my-streams', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'my-streams.html'));
});

// Viewer page
app.get('/live/:name', async (req, res) => {
  const stream = await streams.getStream(req.params.name);
  if (!stream) {
    return res.status(404).send('Stream not found');
  }

  res.sendFile(path.join(__dirname, 'public', 'viewer.html'));
});

// Background: poll MediaMTX, update statuses, handle lifecycle, reconcile Jibri
async function pollStreamStatus() {
  try {
    const activeKeys = await mediamtx.getActiveStreamKeys();
    const allStreams = await streams.listStreams();

    for (const s of allStreams) {
      const isLive = activeKeys.includes(s.key);

      if (isLive && s.status !== 'live') {
        await streams.updateStatus(s.name, 'live');
        console.log(`[poll] Stream "${s.name}" is now live`);
      } else if (!isLive && s.status === 'live') {
        // Was live, now offline → completed
        await streams.markCompleted(s.name);
        console.log(`[poll] Stream "${s.name}" completed`);
      }
    }

    // Delete expired streams (never started, window closed)
    const expired = await streams.listExpired();
    for (const s of expired) {
      await streams.deleteStream(s.name);
      console.log(`[poll] Expired stream "${s.name}" deleted`);
    }

    // Delete completed streams after 5 min grace period
    const toCleanup = await streams.listCompletedForCleanup();
    for (const s of toCleanup) {
      await streams.deleteStream(s.name);
      console.log(`[poll] Cleaned up completed stream "${s.name}"`);
    }

    // Reconcile Jibri based on streams that need it
    const jibriCount = await streams.countStreamsNeedingJibri();
    await scaler.reconcile(jibriCount);
  } catch (err) {
    console.error('[poll] Error polling stream status:', err.message);
  }
}

// Start
async function start() {
  console.log('[startup] Running database migration...');
  await migrate();
  console.log('[startup] Database ready');

  // Reconcile Jibri on startup (only count streams that need Jibri now)
  const count = await streams.countStreamsNeedingJibri();
  console.log(`[startup] ${count} streams needing Jibri, reconciling...`);
  await scaler.reconcile(count);

  // Start polling
  setInterval(pollStreamStatus, 15000);

  app.listen(PORT, () => {
    console.log(`[startup] Stream app listening on port ${PORT}`);
  });
}

start().catch(err => {
  console.error('[startup] Fatal error:', err);
  process.exit(1);
});
