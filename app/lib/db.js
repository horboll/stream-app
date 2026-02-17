const { Pool } = require('pg');

const pool = new Pool({
  host: process.env.DATABASE_HOST || 'localhost',
  port: parseInt(process.env.DATABASE_PORT || '5432'),
  database: process.env.DATABASE_NAME || 'live',
  user: process.env.DATABASE_USER || 'live',
  password: process.env.DATABASE_PASSWORD || '',
});

async function migrate() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS streams (
      name TEXT PRIMARY KEY,
      key TEXT UNIQUE NOT NULL,
      created_at TIMESTAMPTZ DEFAULT NOW(),
      status TEXT DEFAULT 'created'
    )
  `);

  // Add owner_email column (idempotent)
  await pool.query(`
    ALTER TABLE streams ADD COLUMN IF NOT EXISTS owner_email TEXT
  `);

  // Add owner_name column (idempotent)
  await pool.query(`
    ALTER TABLE streams ADD COLUMN IF NOT EXISTS owner_name TEXT
  `);

  // Add scheduled_start column (idempotent)
  await pool.query(`
    ALTER TABLE streams ADD COLUMN IF NOT EXISTS scheduled_start TIMESTAMPTZ
  `);

  // Add completed_at column (idempotent)
  await pool.query(`
    ALTER TABLE streams ADD COLUMN IF NOT EXISTS completed_at TIMESTAMPTZ
  `);

  // Admin whitelist table
  await pool.query(`
    CREATE TABLE IF NOT EXISTS admins (
      email TEXT PRIMARY KEY,
      name TEXT,
      created_at TIMESTAMPTZ DEFAULT NOW()
    )
  `);

  // Settings table (key-value, used for admin password hash etc.)
  await pool.query(`
    CREATE TABLE IF NOT EXISTS settings (
      key TEXT PRIMARY KEY,
      value TEXT NOT NULL
    )
  `);
}

module.exports = { pool, migrate };
