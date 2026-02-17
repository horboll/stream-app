const crypto = require('crypto');
const forge = require('node-forge');
const { pool } = require('./db');

const COOKIE_SECRET = process.env.COOKIE_SECRET || crypto.randomBytes(32).toString('hex');
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || '';

// Microsoft UPN OID: 1.3.6.1.4.1.311.20.2.3
const MS_UPN_OID = '1.3.6.1.4.1.311.20.2.3';

// --- Certificate parsing ---

function extractEmailFromPem(escapedCert) {
  if (!escapedCert) return null;

  try {
    const pemData = decodeURIComponent(escapedCert);
    const cert = forge.pki.certificateFromPem(pemData);

    // Try SAN (Subject Alternative Names)
    const sanExt = cert.getExtension('subjectAltName');
    if (sanExt && sanExt.altNames) {
      // 1. RFC822Name (type 1 = email)
      for (const alt of sanExt.altNames) {
        if (alt.type === 1 && alt.value && alt.value.includes('@')) {
          return alt.value.toLowerCase();
        }
      }

      // 2. OtherName UPN (type 0 = otherName)
      for (const alt of sanExt.altNames) {
        if (alt.type === 0 && alt.value) {
          const upn = extractUpnFromOtherName(alt);
          if (upn && upn.includes('@')) {
            return upn.toLowerCase();
          }
        }
      }
    }

    // 3. Fallback: Subject emailAddress
    const emailAttr = cert.subject.getField({ name: 'emailAddress' });
    if (emailAttr && emailAttr.value && emailAttr.value.includes('@')) {
      return emailAttr.value.toLowerCase();
    }

    return null;
  } catch (err) {
    console.error('[auth] Failed to parse PEM certificate:', err.message);
    return null;
  }
}

function extractUpnFromOtherName(otherName) {
  try {
    // node-forge represents OtherName as { type: 0, value: ... }
    // The value may contain the OID and the actual value
    // Try to extract from the raw ASN.1 structure
    if (otherName.value && typeof otherName.value === 'string') {
      if (otherName.value.includes('@')) return otherName.value;
    }

    // If it's an ASN.1 object, try to decode it
    if (otherName.value && Buffer.isBuffer(otherName.value)) {
      return decodeUpnValue(otherName.value);
    }

    // node-forge may give us the value differently
    // Try raw bytes interpretation
    if (otherName.value) {
      const str = String(otherName.value);
      if (str.includes('@')) return str;
    }

    return null;
  } catch (err) {
    return null;
  }
}

function decodeUpnValue(derBytes) {
  if (!derBytes || derBytes.length < 2) return null;

  try {
    const tag = derBytes[0];
    let valueStart, length;

    // Handle multi-byte length encoding
    if (derBytes[1] & 0x80) {
      const numBytes = derBytes[1] & 0x7F;
      if (numBytes > 2 || derBytes.length < 2 + numBytes) return null;
      length = 0;
      for (let i = 0; i < numBytes; i++) {
        length = (length << 8) | derBytes[2 + i];
      }
      valueStart = 2 + numBytes;
    } else {
      length = derBytes[1];
      valueStart = 2;
    }

    const valueBytes = derBytes.slice(valueStart, valueStart + length);

    // Tag 0x0C = UTF8String
    if (tag === 0x0C) {
      return valueBytes.toString('utf-8');
    }

    // Tag 0xA0 = context-specific [0] (explicit tag wrapping) — recurse
    if (tag === 0xA0) {
      return decodeUpnValue(valueBytes);
    }

    // Fallback: try raw UTF-8 decode
    const decoded = derBytes.toString('utf-8').replace(/[^\x20-\x7E]/g, '');
    if (decoded.includes('@')) {
      const parts = decoded.split(/\s+/);
      for (const part of parts) {
        if (part.includes('@')) return part;
      }
    }

    return null;
  } catch (err) {
    return null;
  }
}

function extractNameFromPem(escapedCert) {
  if (!escapedCert) return null;

  try {
    const pemData = decodeURIComponent(escapedCert);
    const cert = forge.pki.certificateFromPem(pemData);
    const cnField = cert.subject.getField('CN');
    return cnField && cnField.value ? cnField.value : null;
  } catch (err) {
    return null;
  }
}

function extractEmailFromCertInfo(certInfo) {
  if (!certInfo) return null;

  try {
    const decoded = decodeURIComponent(certInfo);

    // Try SAN email (Traefik format: Subject="...";Issuer="...";SAN="email@example.com")
    for (const part of decoded.split(';')) {
      const trimmed = part.trim();
      if (trimmed.startsWith('SAN=')) {
        const sanValue = trimmed.slice(4).replace(/"/g, '');
        for (const san of sanValue.split(',')) {
          const s = san.trim();
          if (s.includes('@')) return s.toLowerCase();
        }
      }
    }

    // Fallback: try Subject fields for email
    for (const part of decoded.split(';')) {
      const trimmed = part.trim();
      if (trimmed.startsWith('Subject=')) {
        const subject = trimmed.slice(8).replace(/"/g, '');
        for (const field of subject.split(',')) {
          const f = field.trim();
          if (f.includes('@')) {
            const val = f.includes('=') ? f.split('=').pop().trim() : f;
            return val.toLowerCase();
          }
        }
      }
    }

    return null;
  } catch (err) {
    return null;
  }
}

// --- Cookie signing ---

function signToken(payload) {
  const data = JSON.stringify(payload);
  const b64 = Buffer.from(data).toString('base64');
  const sig = crypto.createHmac('sha256', COOKIE_SECRET).update(b64).digest('base64url');
  return `${b64}.${sig}`;
}

function verifyToken(token) {
  if (!token || !token.includes('.')) return null;
  const [b64, sig] = token.split('.');
  const expected = crypto.createHmac('sha256', COOKIE_SECRET).update(b64).digest('base64url');
  if (sig !== expected) return null;

  try {
    const payload = JSON.parse(Buffer.from(b64, 'base64').toString());
    if (payload.exp && Date.now() > payload.exp) return null;
    return payload;
  } catch {
    return null;
  }
}

// --- Admin password management ---

function hashPassword(password) {
  const salt = crypto.randomBytes(16).toString('hex');
  const hash = crypto.scryptSync(password, salt, 64).toString('hex');
  return `${salt}:${hash}`;
}

function verifyPassword(password, stored) {
  const [salt, hash] = stored.split(':');
  const check = crypto.scryptSync(password, salt, 64).toString('hex');
  return hash === check;
}

async function getStoredPassword() {
  const result = await pool.query("SELECT value FROM settings WHERE key = 'admin_password_hash'");
  return result.rows[0]?.value || null;
}

async function setStoredPassword(password) {
  const hashed = hashPassword(password);
  await pool.query(
    "INSERT INTO settings (key, value) VALUES ('admin_password_hash', $1) ON CONFLICT (key) DO UPDATE SET value = $1",
    [hashed]
  );
}

async function isPasswordChanged() {
  const stored = await getStoredPassword();
  return stored !== null;
}

async function checkAdminPassword(password) {
  // Check DB password first (set after first login)
  const stored = await getStoredPassword();
  if (stored) {
    return verifyPassword(password, stored);
  }
  // Fall back to env var (initial password)
  return ADMIN_PASSWORD && password === ADMIN_PASSWORD;
}

// --- Admin CRUD ---

async function getAdmins() {
  const result = await pool.query('SELECT * FROM admins ORDER BY created_at');
  return result.rows;
}

async function isAdmin(email) {
  if (!email) return false;
  const result = await pool.query('SELECT 1 FROM admins WHERE email = $1', [email.toLowerCase()]);
  return result.rows.length > 0;
}

async function addAdmin(email, name) {
  const result = await pool.query(
    'INSERT INTO admins (email, name) VALUES ($1, $2) ON CONFLICT (email) DO UPDATE SET name = $2 RETURNING *',
    [email.toLowerCase(), name || '']
  );
  return result.rows[0];
}

async function removeAdmin(email) {
  const result = await pool.query('DELETE FROM admins WHERE email = $1 RETURNING *', [email.toLowerCase()]);
  return result.rows[0] || null;
}

module.exports = {
  extractEmailFromPem,
  extractNameFromPem,
  extractEmailFromCertInfo,
  signToken,
  verifyToken,
  checkAdminPassword,
  isPasswordChanged,
  setStoredPassword,
  getAdmins,
  isAdmin,
  addAdmin,
  removeAdmin,
};
