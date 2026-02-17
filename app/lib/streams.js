const crypto = require('crypto');
const { pool } = require('./db');

function generateKey() {
  return crypto.randomBytes(16).toString('hex');
}

async function createStream(name, ownerEmail, ownerName, scheduledStart) {
  const key = generateKey();
  const result = await pool.query(
    'INSERT INTO streams (name, key, owner_email, owner_name, scheduled_start) VALUES ($1, $2, $3, $4, $5) RETURNING *',
    [name, key, ownerEmail ? ownerEmail.toLowerCase() : null, ownerName || null, scheduledStart || new Date()]
  );
  return result.rows[0];
}

async function getStream(name) {
  const result = await pool.query('SELECT * FROM streams WHERE name = $1', [name]);
  return result.rows[0] || null;
}

async function getStreamByKey(key) {
  const result = await pool.query('SELECT * FROM streams WHERE key = $1', [key]);
  return result.rows[0] || null;
}

async function listStreams() {
  const result = await pool.query('SELECT * FROM streams ORDER BY scheduled_start ASC, created_at DESC');
  return result.rows;
}

async function listByOwner(email) {
  const result = await pool.query(
    'SELECT * FROM streams WHERE LOWER(owner_email) = $1 ORDER BY scheduled_start ASC, created_at DESC',
    [email.toLowerCase()]
  );
  return result.rows;
}

async function deleteStream(name) {
  const result = await pool.query('DELETE FROM streams WHERE name = $1 RETURNING *', [name]);
  return result.rows[0] || null;
}

async function updateStatus(name, status) {
  await pool.query('UPDATE streams SET status = $1 WHERE name = $2', [status, name]);
}

async function markCompleted(name) {
  await pool.query(
    "UPDATE streams SET status = 'completed', completed_at = NOW() WHERE name = $1",
    [name]
  );
}

async function countStreamsNeedingJibri() {
  const result = await pool.query(`
    SELECT COUNT(*) as count FROM streams
    WHERE status IN ('created', 'live')
      AND (scheduled_start IS NULL
           OR (NOW() >= scheduled_start - INTERVAL '90 minutes'
               AND NOW() <= scheduled_start + INTERVAL '24 hours'))
  `);
  const count = parseInt(result.rows[0].count);
  // Always keep one extra Jibri warm so new streams don't have to wait for boot
  return count > 0 ? count + 1 : 0;
}

async function listExpired() {
  const result = await pool.query(`
    SELECT * FROM streams
    WHERE status = 'created'
      AND scheduled_start IS NOT NULL
      AND NOW() > scheduled_start + INTERVAL '24 hours'
  `);
  return result.rows;
}

async function listCompletedForCleanup() {
  const result = await pool.query(`
    SELECT * FROM streams
    WHERE status = 'completed'
      AND completed_at IS NOT NULL
      AND NOW() > completed_at + INTERVAL '5 minutes'
  `);
  return result.rows;
}

module.exports = {
  createStream, getStream, getStreamByKey, listStreams, listByOwner,
  deleteStream, updateStatus, markCompleted,
  countStreamsNeedingJibri, listExpired, listCompletedForCleanup,
};
