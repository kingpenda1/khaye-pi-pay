'use strict';

const express = require('express');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const crypto = require('node:crypto');
const path = require('node:path');
const { openDatabase, withTransaction } = require('./db');
const { parsePiAmount, formatPiAmount } = require('./lib/money');

const app = express();
const PORT = Number(process.env.PORT || 3000);
const PI_API = (process.env.PI_API_BASE_URL || 'https://api.minepi.com/v2').replace(/\/$/, '');
const PI_API_KEY = process.env.PI_API_KEY;
const SANDBOX = String(process.env.PI_SANDBOX || 'true').toLowerCase() === 'true';
const INTENT_TTL_MS = 15 * 60 * 1000;
const DEFAULT_INVOICE_TTL_MS = 30 * 60 * 1000;
const MAX_INVOICE_TTL_MS = 24 * 60 * 60 * 1000;
const db = openDatabase();

app.disable('x-powered-by');
app.use(helmet({ contentSecurityPolicy: false }));
app.use(express.json({ limit: '20kb', strict: true }));
app.use('/api/', rateLimit({ windowMs: 60_000, limit: 60, standardHeaders: true, legacyHeaders: false }));
app.use(express.static(path.join(__dirname, 'public')));

function httpError(status, message) {
  const error = new Error(message);
  error.status = status;
  return error;
}

async function readJson(response) {
  return response.json().catch(() => ({}));
}

async function piRequest(endpoint, options = {}) {
  if (!PI_API_KEY || PI_API_KEY === 'replace_with_server_api_key') {
    throw httpError(503, 'The server has not been configured with its Pi Developer Server API Key.');
  }
  const response = await fetch(`${PI_API}${endpoint}`, {
    ...options,
    signal: options.signal || AbortSignal.timeout(12_000),
    headers: { Authorization: `Key ${PI_API_KEY}`, ...(options.headers || {}) }
  });
  const data = await readJson(response);
  if (!response.ok) {
    const message = typeof data.error === 'string' ? data.error : `Pi Platform API returned HTTP ${response.status}`;
    throw httpError(response.status >= 400 && response.status < 500 ? response.status : 502, message);
  }
  return data;
}

async function requirePiUser(req, res, next) {
  try {
    const match = /^Bearer\s+([^\s]+)$/i.exec(req.get('authorization') || '');
    if (!match) return res.status(401).json({ error: 'Sign in with Pi first.' });
    const response = await fetch(`${PI_API}/me`, {
      headers: { Authorization: `Bearer ${match[1]}` },
      signal: AbortSignal.timeout(10_000)
    });
    const user = await readJson(response);
    if (!response.ok || typeof user.uid !== 'string' || !user.uid) {
      return res.status(401).json({ error: 'Pi could not verify this account. Please sign in again.' });
    }
    const now = Date.now();
    db.prepare(`INSERT INTO users (pi_uid, username, created_at, last_seen_at)
      VALUES (?, ?, ?, ?)
      ON CONFLICT(pi_uid) DO UPDATE SET username=excluded.username, last_seen_at=excluded.last_seen_at`)
      .run(user.uid, typeof user.username === 'string' ? user.username : null, now, now);
    req.piUser = { uid: user.uid, username: user.username || null };
    next();
  } catch (error) {
    if (error.status) return res.status(error.status).json({ error: error.message });
    res.status(503).json({ error: 'Pi identity verification is temporarily unavailable.' });
  }
}

function requireMerchant(req, res, next) {
  const merchant = db.prepare('SELECT pi_uid, display_name FROM merchants WHERE pi_uid = ?').get(req.piUser.uid);
  if (!merchant) return res.status(403).json({ error: 'Create your merchant profile before creating invoices.' });
  req.merchant = merchant;
  next();
}

function amountFromRequest(value) {
  const micros = parsePiAmount(value);
  if (micros === null) throw httpError(400, 'Enter a Pi amount greater than zero with no more than 7 decimal places (maximum 1,000,000 Pi).');
  return micros;
}

function invoiceCode() {
  return `KP-${crypto.randomBytes(16).toString('hex').toUpperCase()}`;
}

function publicInvoice(row) {
  return {
    code: row.code,
    merchantName: row.display_name,
    merchantUsername: row.username || null,
    amount: formatPiAmount(row.amount_micros),
    memo: row.memo,
    status: row.status,
    createdAt: row.created_at,
    expiresAt: row.expires_at
  };
}

function getInvoiceByCode(code) {
  return db.prepare(`SELECT i.*, m.display_name, u.username
    FROM invoices i JOIN merchants m ON m.pi_uid=i.merchant_uid
    JOIN users u ON u.pi_uid=m.pi_uid WHERE i.code=?`).get(code.toUpperCase());
}

function getIntent(intentId) {
  return db.prepare(`SELECT p.*, i.code AS invoice_code, i.merchant_uid, i.status AS invoice_status,
      i.expires_at AS invoice_expires_at, i.payment_id AS invoice_payment_id
    FROM payment_intents p JOIN invoices i ON i.id=p.invoice_id WHERE p.id=?`).get(intentId);
}

function assertPaymentMatches(payment, intent) {
  const metadata = payment && payment.metadata && typeof payment.metadata === 'object' ? payment.metadata : {};
  return Boolean(payment &&
    payment.identifier &&
    payment.user_uid === intent.payer_uid &&
    parsePiAmount(payment.amount) === intent.amount_micros &&
    payment.memo === intent.memo &&
    metadata.app === 'KHAYE_PI_PAY' &&
    metadata.intentId === intent.id &&
    metadata.invoiceId === intent.invoice_id &&
    metadata.invoiceCode === intent.invoice_code &&
    !payment.status?.cancelled && !payment.status?.user_cancelled);
}

function expireInvoiceIfNeeded(invoice) {
  const now = Date.now();
  if (!invoice) return invoice;
  if (invoice.status === 'open' && invoice.expires_at <= now) {
    db.prepare("UPDATE invoices SET status='expired' WHERE id=? AND status='open'").run(invoice.id);
    return { ...invoice, status: 'expired' };
  }
  if (invoice.status === 'payment_pending') {
    const active = db.prepare(`SELECT id, status, expires_at FROM payment_intents
      WHERE invoice_id=? AND status IN ('created','approving','approved')`).get(invoice.id);
    // Only expire an intent that never reached Pi server approval. Never release an
    // invoice while an external Pi approval/transaction may still be in flight.
    if (active?.status === 'created' && active.expires_at <= now) {
      db.prepare("UPDATE payment_intents SET status='expired' WHERE id=? AND status='created'").run(active.id);
      const nextStatus = invoice.expires_at <= now ? 'expired' : 'open';
      db.prepare("UPDATE invoices SET status=?, payment_id=NULL WHERE id=? AND status='payment_pending' AND payment_id IS NULL")
        .run(nextStatus, invoice.id);
      return { ...invoice, status: nextStatus, payment_id: null };
    }
    if (!active && invoice.expires_at <= now && !invoice.payment_id) {
      db.prepare("UPDATE invoices SET status='expired' WHERE id=? AND status='payment_pending'").run(invoice.id);
      return { ...invoice, status: 'expired' };
    }
  }
  return invoice;
}

function markInvoicePaid(intent, txid) {
  withTransaction(db, () => {
    const fresh = db.prepare('SELECT * FROM payment_intents WHERE id=?').get(intent.id);
    if (!fresh) throw httpError(404, 'The payment request could not be found.');
    if (fresh.status === 'completed') {
      if (fresh.txid !== txid) throw httpError(409, 'This payment was completed with a different transaction ID.');
      return;
    }
    if (fresh.payment_id !== intent.payment_id || fresh.payer_uid !== intent.payer_uid) {
      throw httpError(409, 'The saved payment request changed during completion.');
    }
    const invoice = db.prepare('SELECT * FROM invoices WHERE id=?').get(fresh.invoice_id);
    if (!invoice || invoice.payment_id !== fresh.payment_id || invoice.status !== 'payment_pending') {
      if (invoice?.status === 'paid' && invoice.payment_id === fresh.payment_id) return;
      throw httpError(409, 'The invoice is no longer awaiting this payment. Contact the merchant before retrying.');
    }
    const now = Date.now();
    db.prepare("UPDATE payment_intents SET status='completed', txid=?, completed_at=? WHERE id=?")
      .run(txid, now, fresh.id);
    db.prepare("UPDATE invoices SET status='paid', paid_at=?, paid_by_uid=? WHERE id=? AND payment_id=? AND status='payment_pending'")
      .run(now, fresh.payer_uid, fresh.invoice_id, fresh.payment_id);
  });
}

async function completeVerifiedPayment(intent, txid) {
  if (!intent || !intent.payment_id) throw httpError(404, 'No saved payment matches this request.');
  if (intent.status === 'completed') return { completed: true, alreadyCompleted: true };
  if (!['approved', 'approving'].includes(intent.status)) throw httpError(409, 'The payment has not been approved by the server yet.');

  const payment = await piRequest(`/payments/${encodeURIComponent(intent.payment_id)}`);
  if (!assertPaymentMatches(payment, intent)) throw httpError(403, 'Pi payment details do not match this invoice and verified customer.');
  if (intent.status === 'approving' && payment.status?.developer_approved === true) {
    db.prepare("UPDATE payment_intents SET status='approved' WHERE id=? AND payment_id=? AND status='approving'")
      .run(intent.id, intent.payment_id);
    intent.status = 'approved';
  }
  if (intent.status !== 'approved') throw httpError(409, 'Pi has not confirmed server-side approval yet.');
  if (!payment.transaction || payment.transaction.txid !== txid || payment.transaction.verified !== true) {
    throw httpError(409, 'Pi has not verified this blockchain transaction yet.');
  }

  let finalPayment = payment;
  if (payment.status?.developer_completed !== true) {
    finalPayment = await piRequest(`/payments/${encodeURIComponent(intent.payment_id)}/complete`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ txid })
    });
    if (finalPayment.status?.developer_completed !== true) {
      finalPayment = await piRequest(`/payments/${encodeURIComponent(intent.payment_id)}`);
    }
  }
  if (finalPayment.status?.developer_completed !== true) {
    throw httpError(502, 'Pi has not confirmed server-side completion. The invoice remains unpaid in KHAYE PI PAY.');
  }

  markInvoicePaid(intent, txid);
  return { completed: true };
}

app.get('/api/config', (_req, res) => {
  res.json({ sandbox: SANDBOX, appName: 'KHAYE PI PAY' });
});

app.post('/api/verify', requirePiUser, (req, res) => {
  res.json({ uid: req.piUser.uid, username: req.piUser.username });
});

app.get('/api/merchant/me', requirePiUser, (req, res) => {
  const merchant = db.prepare('SELECT display_name, created_at FROM merchants WHERE pi_uid=?').get(req.piUser.uid);
  res.json({ merchant: merchant || null });
});

app.post('/api/merchant/register', requirePiUser, (req, res) => {
  const displayName = typeof req.body?.displayName === 'string' ? req.body.displayName.trim() : '';
  if (displayName.length < 2 || displayName.length > 40) {
    return res.status(400).json({ error: 'Store name must be between 2 and 40 characters.' });
  }
  const now = Date.now();
  db.prepare(`INSERT INTO merchants (pi_uid, display_name, created_at, updated_at)
    VALUES (?, ?, ?, ?)
    ON CONFLICT(pi_uid) DO UPDATE SET display_name=excluded.display_name, updated_at=excluded.updated_at`)
    .run(req.piUser.uid, displayName, now, now);
  res.status(201).json({ merchant: { displayName } });
});

app.post('/api/invoices', requirePiUser, requireMerchant, (req, res) => {
  try {
    const amountMicros = amountFromRequest(req.body?.amount);
    const memo = typeof req.body?.memo === 'string' ? req.body.memo.trim() : '';
    if (memo.length < 1 || memo.length > 80) throw httpError(400, 'Invoice description must be 1–80 characters.');
    const ttlMinutes = Number(req.body?.expiresInMinutes || 30);
    if (!Number.isInteger(ttlMinutes) || ttlMinutes < 5 || ttlMinutes > 1440) {
      throw httpError(400, 'Invoice expiry must be between 5 minutes and 24 hours.');
    }
    const now = Date.now();
    const id = crypto.randomUUID();
    const code = invoiceCode();
    const expiresAt = now + Math.min(ttlMinutes * 60_000, MAX_INVOICE_TTL_MS);
    db.prepare(`INSERT INTO invoices (id, code, merchant_uid, amount_micros, memo, status, created_at, expires_at)
      VALUES (?, ?, ?, ?, ?, 'open', ?, ?)`).run(id, code, req.piUser.uid, amountMicros, memo, now, expiresAt);
    const row = getInvoiceByCode(code);
    res.status(201).json({ invoice: publicInvoice(row) });
  } catch (error) {
    res.status(error.status || 500).json({ error: error.message || 'Could not create invoice.' });
  }
});

app.get('/api/invoices/:code', (req, res) => {
  const code = String(req.params.code || '').trim().toUpperCase();
  if (!/^KP-[A-F0-9]{32}$/.test(code)) return res.status(400).json({ error: 'That KHAYE payment code is not valid.' });
  const row = getInvoiceByCode(code);
  if (!row) return res.status(404).json({ error: 'No invoice was found for that payment code.' });
  const current = expireInvoiceIfNeeded(row);
  if (current.status === 'expired') return res.status(410).json({ error: 'This invoice has expired. Ask the merchant for a new code.' });
  res.json({ invoice: publicInvoice(current) });
});

app.get('/api/merchant/invoices', requirePiUser, requireMerchant, (req, res) => {
  const rows = db.prepare(`SELECT i.*, m.display_name, u.username FROM invoices i
    JOIN merchants m ON m.pi_uid=i.merchant_uid JOIN users u ON u.pi_uid=m.pi_uid
    WHERE i.merchant_uid=? ORDER BY i.created_at DESC LIMIT 50`).all(req.piUser.uid);
  res.json({ invoices: rows.map(row => publicInvoice(expireInvoiceIfNeeded(row))) });
});

app.post('/api/payment-intents', requirePiUser, (req, res) => {
  try {
    const code = typeof req.body?.invoiceCode === 'string' ? req.body.invoiceCode.trim().toUpperCase() : '';
    if (!/^KP-[A-F0-9]{32}$/.test(code)) throw httpError(400, 'Enter a valid KHAYE merchant payment code.');
    const result = withTransaction(db, () => {
      let invoice = getInvoiceByCode(code);
      if (!invoice) throw httpError(404, 'No invoice was found for that payment code.');
      invoice = expireInvoiceIfNeeded(invoice);
      if (invoice.status === 'expired' || invoice.expires_at <= Date.now()) throw httpError(410, 'This invoice has expired.');
      if (invoice.status === 'paid') throw httpError(409, 'This invoice has already been paid.');
      if (invoice.merchant_uid === req.piUser.uid) throw httpError(400, 'A merchant cannot pay their own invoice using the same Pi account.');

      let active = db.prepare(`SELECT * FROM payment_intents WHERE invoice_id=?
        AND status IN ('created','approving','approved')`).get(invoice.id);
      if (active && active.expires_at <= Date.now() && active.status === 'created') {
        db.prepare("UPDATE payment_intents SET status='expired' WHERE id=?").run(active.id);
        db.prepare("UPDATE invoices SET status='open', payment_id=NULL WHERE id=? AND status='payment_pending'").run(invoice.id);
        active = null;
        invoice = db.prepare('SELECT * FROM invoices WHERE id=?').get(invoice.id);
      }
      if (active) {
        if (active.payer_uid !== req.piUser.uid) throw httpError(409, 'This invoice already has a payment in progress. Ask the customer using it to finish or cancel.');
        if (active.status !== 'created') throw httpError(409, 'A Pi payment is already being processed for this invoice. Do not start a second payment; return to Pi Browser to finish or contact the merchant.');
        return { intent: active, invoice, reused: true };
      }
      if (invoice.status !== 'open') throw httpError(409, 'This invoice is not available for payment.');

      const now = Date.now();
      const intentId = crypto.randomUUID();
      const intentExpiry = Math.min(now + INTENT_TTL_MS, invoice.expires_at);
      const paymentMemo = `KP ${invoice.code}: ${invoice.memo}`;
      db.prepare(`INSERT INTO payment_intents (id, invoice_id, payer_uid, amount_micros, memo, status, created_at, expires_at)
        VALUES (?, ?, ?, ?, ?, 'created', ?, ?)`)
        .run(intentId, invoice.id, req.piUser.uid, invoice.amount_micros, paymentMemo, now, intentExpiry);
      db.prepare("UPDATE invoices SET status='payment_pending' WHERE id=? AND status='open'").run(invoice.id);
      return { intent: getIntent(intentId), invoice, reused: false };
    });
    res.status(result.reused ? 200 : 201).json({
      intentId: result.intent.id,
      invoiceId: result.intent.invoice_id,
      invoiceCode: result.invoice.code,
      amount: formatPiAmount(result.intent.amount_micros),
      memo: result.intent.memo,
      expiresAt: result.intent.expires_at,
      reused: result.reused
    });
  } catch (error) {
    if (error.status === 410) {
      const code = typeof req.body?.invoiceCode === 'string' ? req.body.invoiceCode.trim().toUpperCase() : '';
      if (/^KP-[A-F0-9]{32}$/.test(code)) expireInvoiceIfNeeded(getInvoiceByCode(code));
    }
    res.status(error.status || 500).json({ error: error.message || 'Could not start payment.' });
  }
});

app.post('/api/payments/approve', requirePiUser, async (req, res) => {
  try {
    const { paymentId, intentId } = req.body || {};
    if (typeof paymentId !== 'string' || !paymentId || typeof intentId !== 'string' || !intentId) {
      throw httpError(400, 'paymentId and intentId are required.');
    }
    const intent = getIntent(intentId);
    if (!intent || intent.payer_uid !== req.piUser.uid) throw httpError(403, 'This payment request does not belong to your verified Pi account.');
    if (intent.status === 'completed') {
      if (intent.payment_id !== paymentId) throw httpError(409, 'This request is already linked to another payment.');
      return res.json({ approved: true, alreadyCompleted: true });
    }
    if (intent.status === 'created' && intent.expires_at <= Date.now()) throw httpError(410, 'This payment request has expired.');
    if (intent.payment_id && intent.payment_id !== paymentId) throw httpError(409, 'This invoice is already linked to a different Pi payment.');

    const payment = await piRequest(`/payments/${encodeURIComponent(paymentId)}`);
    if (!assertPaymentMatches(payment, intent)) throw httpError(403, 'Pi payment does not match this verified customer and merchant invoice.');
    if (payment.status?.cancelled || payment.status?.user_cancelled) throw httpError(409, 'This Pi payment was cancelled.');

    withTransaction(db, () => {
      const fresh = getIntent(intentId);
      if (!fresh || fresh.payer_uid !== req.piUser.uid) throw httpError(403, 'Payment request ownership changed.');
      if (fresh.payment_id && fresh.payment_id !== paymentId) throw httpError(409, 'Another Pi payment is already linked to this invoice.');
      if (fresh.status === 'created' && fresh.expires_at <= Date.now()) throw httpError(410, 'This payment request has expired.');
      if (!['created', 'approving', 'approved'].includes(fresh.status)) throw httpError(409, 'This payment request cannot be approved in its current state.');
      db.prepare("UPDATE payment_intents SET payment_id=?, status=CASE WHEN status='approved' THEN status ELSE 'approving' END WHERE id=?")
        .run(paymentId, intentId);
      db.prepare(`UPDATE invoices SET payment_id=? WHERE id=? AND status='payment_pending'
        AND (payment_id IS NULL OR payment_id=?)`).run(paymentId, fresh.invoice_id, paymentId);
      const invoice = db.prepare('SELECT status, payment_id FROM invoices WHERE id=?').get(fresh.invoice_id);
      if (!invoice || invoice.status !== 'payment_pending' || invoice.payment_id !== paymentId) {
        throw httpError(409, 'The invoice is no longer available for this payment.');
      }
    });

    let approved = payment;
    if (payment.status?.developer_approved !== true) {
      approved = await piRequest(`/payments/${encodeURIComponent(paymentId)}/approve`, { method: 'POST' });
    }
    if (approved.status?.developer_approved !== true) throw httpError(502, 'Pi did not confirm server-side approval. Retry this same payment in Pi Browser.');
    db.prepare("UPDATE payment_intents SET status='approved' WHERE id=? AND payment_id=? AND status IN ('approving','approved')")
      .run(intentId, paymentId);
    res.json({ approved: true });
  } catch (error) {
    res.status(error.status || 502).json({ error: error.message || 'Payment approval failed.' });
  }
});

app.post('/api/payments/complete', requirePiUser, async (req, res) => {
  try {
    const { paymentId, txid, intentId } = req.body || {};
    if (typeof paymentId !== 'string' || !paymentId || typeof txid !== 'string' || !txid || typeof intentId !== 'string' || !intentId) {
      throw httpError(400, 'paymentId, txid and intentId are required.');
    }
    const intent = getIntent(intentId);
    if (!intent || intent.payer_uid !== req.piUser.uid || intent.payment_id !== paymentId) {
      throw httpError(403, 'This payment is not linked to your verified account and invoice.');
    }
    const result = await completeVerifiedPayment(intent, txid);
    res.json(result);
  } catch (error) {
    res.status(error.status || 502).json({ error: error.message || 'Payment completion failed.' });
  }
});

app.post('/api/payments/recover', requirePiUser, async (req, res) => {
  try {
    const { paymentId, txid } = req.body || {};
    if (typeof paymentId !== 'string' || !paymentId || typeof txid !== 'string' || !txid) {
      throw httpError(400, 'paymentId and txid are required.');
    }
    const intent = db.prepare(`SELECT p.*, i.code AS invoice_code, i.merchant_uid, i.status AS invoice_status,
      i.expires_at AS invoice_expires_at, i.payment_id AS invoice_payment_id
      FROM payment_intents p JOIN invoices i ON i.id=p.invoice_id WHERE p.payment_id=?`).get(paymentId);
    if (!intent || intent.payer_uid !== req.piUser.uid) throw httpError(403, 'No saved KHAYE PI PAY invoice matches this payment.');
    const result = await completeVerifiedPayment(intent, txid);
    res.json(result);
  } catch (error) {
    res.status(error.status || 502).json({ error: error.message || 'Payment recovery failed.' });
  }
});

app.post('/api/payments/cancel', requirePiUser, async (req, res) => {
  try {
    const { intentId, paymentId } = req.body || {};
    if (typeof intentId !== 'string' || !intentId) throw httpError(400, 'intentId is required.');
    const intent = getIntent(intentId);
    if (!intent || intent.payer_uid !== req.piUser.uid) throw httpError(403, 'This payment request does not belong to your account.');
    if (intent.status === 'completed') throw httpError(409, 'A completed payment cannot be cancelled.');
    if (intent.payment_id) {
      if (paymentId !== intent.payment_id) throw httpError(409, 'The Pi payment ID does not match this request.');
      const payment = await piRequest(`/payments/${encodeURIComponent(intent.payment_id)}`);
      if ((!payment.status?.cancelled && !payment.status?.user_cancelled) || payment.transaction?.verified === true) {
        throw httpError(409, 'Pi has not confirmed a safe cancellation for this payment.');
      }
    } else if (paymentId) {
      throw httpError(409, 'This payment ID is not saved against the invoice.');
    }
    withTransaction(db, () => {
      db.prepare("UPDATE payment_intents SET status='cancelled' WHERE id=? AND payer_uid=? AND status IN ('created','approving','approved')")
        .run(intentId, req.piUser.uid);
      const invoice = db.prepare('SELECT status, expires_at FROM invoices WHERE id=?').get(intent.invoice_id);
      if (invoice?.status === 'payment_pending') {
        const nextStatus = invoice.expires_at <= Date.now() ? 'expired' : 'open';
        db.prepare('UPDATE invoices SET status=?, payment_id=NULL WHERE id=? AND status=\'payment_pending\'')
          .run(nextStatus, intent.invoice_id);
      }
    });
    res.json({ cancelled: true });
  } catch (error) {
    res.status(error.status || 502).json({ error: error.message || 'Could not cancel this payment request.' });
  }
});

app.get('/api/activity', requirePiUser, (req, res) => {
  const rows = db.prepare(`SELECT p.id, p.amount_micros, p.memo, p.completed_at, p.payer_uid,
      i.code, i.merchant_uid, m.display_name, u.username
    FROM payment_intents p JOIN invoices i ON i.id=p.invoice_id
    JOIN merchants m ON m.pi_uid=i.merchant_uid JOIN users u ON u.pi_uid=m.pi_uid
    WHERE p.status='completed' AND (p.payer_uid=? OR i.merchant_uid=?)
    ORDER BY p.completed_at DESC LIMIT 50`).all(req.piUser.uid, req.piUser.uid);
  res.json({ activity: rows.map(row => ({
    id: row.id,
    direction: row.payer_uid === req.piUser.uid ? 'paid' : 'received',
    amount: formatPiAmount(row.amount_micros),
    memo: row.memo,
    invoiceCode: row.code,
    merchantName: row.display_name,
    completedAt: row.completed_at
  })) });
});

app.get('/health', (_req, res) => {
  res.json({ ok: true, app: 'KHAYE PI PAY', sandbox: SANDBOX, storage: 'sqlite-durable-single-instance' });
});

app.use((error, _req, res, _next) => {
  if (res.headersSent) return;
  res.status(error.status || 500).json({ error: error.status ? error.message : 'Unexpected server error.' });
});

const server = app.listen(PORT, () => {
  console.log(`KHAYE PI PAY listening on port ${PORT} (${SANDBOX ? 'Pi Sandbox' : 'Production'})`);
});

function shutdown() {
  server.close(() => {
    try { db.close(); } finally { process.exit(0); }
  });
}
process.on('SIGINT', shutdown);
process.on('SIGTERM', shutdown);

module.exports = { app, db };
