'use strict';

const fs = require('node:fs');
const path = require('node:path');
const { DatabaseSync } = require('node:sqlite');

function openDatabase(databasePath = process.env.DB_PATH || './data/khaye-pi-pay.sqlite') {
  const resolved = path.resolve(databasePath);
  fs.mkdirSync(path.dirname(resolved), { recursive: true });
  const db = new DatabaseSync(resolved);
  db.exec(`
    PRAGMA foreign_keys = ON;
    PRAGMA journal_mode = WAL;
    PRAGMA synchronous = FULL;
    PRAGMA busy_timeout = 5000;

    CREATE TABLE IF NOT EXISTS users (
      pi_uid TEXT PRIMARY KEY,
      username TEXT,
      created_at INTEGER NOT NULL,
      last_seen_at INTEGER NOT NULL
    );

    CREATE TABLE IF NOT EXISTS merchants (
      pi_uid TEXT PRIMARY KEY REFERENCES users(pi_uid),
      display_name TEXT NOT NULL,
      created_at INTEGER NOT NULL,
      updated_at INTEGER NOT NULL
    );

    CREATE TABLE IF NOT EXISTS invoices (
      id TEXT PRIMARY KEY,
      code TEXT NOT NULL UNIQUE,
      merchant_uid TEXT NOT NULL REFERENCES merchants(pi_uid),
      amount_micros INTEGER NOT NULL CHECK (amount_micros > 0),
      memo TEXT NOT NULL,
      status TEXT NOT NULL CHECK (status IN ('open','payment_pending','paid','cancelled','expired')),
      created_at INTEGER NOT NULL,
      expires_at INTEGER NOT NULL,
      paid_at INTEGER,
      paid_by_uid TEXT REFERENCES users(pi_uid),
      payment_id TEXT UNIQUE
    );

    CREATE TABLE IF NOT EXISTS payment_intents (
      id TEXT PRIMARY KEY,
      invoice_id TEXT NOT NULL REFERENCES invoices(id),
      payer_uid TEXT NOT NULL REFERENCES users(pi_uid),
      amount_micros INTEGER NOT NULL CHECK (amount_micros > 0),
      memo TEXT NOT NULL,
      status TEXT NOT NULL CHECK (status IN ('created','approving','approved','completed','cancelled','expired')),
      created_at INTEGER NOT NULL,
      expires_at INTEGER NOT NULL,
      payment_id TEXT UNIQUE,
      txid TEXT UNIQUE,
      completed_at INTEGER
    );

    CREATE UNIQUE INDEX IF NOT EXISTS one_active_intent_per_invoice
      ON payment_intents(invoice_id)
      WHERE status IN ('created','approving','approved');

    CREATE INDEX IF NOT EXISTS invoices_merchant_created
      ON invoices(merchant_uid, created_at DESC);
    CREATE INDEX IF NOT EXISTS payment_intents_payer_created
      ON payment_intents(payer_uid, created_at DESC);
    CREATE INDEX IF NOT EXISTS invoices_status_expiry
      ON invoices(status, expires_at);
  `);
  return db;
}

function withTransaction(db, work) {
  db.exec('BEGIN IMMEDIATE');
  try {
    const result = work();
    db.exec('COMMIT');
    return result;
  } catch (error) {
    try { db.exec('ROLLBACK'); } catch { /* retain the original error */ }
    throw error;
  }
}

module.exports = { openDatabase, withTransaction };
