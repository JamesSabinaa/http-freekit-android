import { DatabaseSync, constants as sqlite } from 'node:sqlite';
import { createHash, randomBytes as secureRandom, timingSafeEqual } from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { performance } from 'node:perf_hooks';
import { inspect } from 'node:util';
import { enrollmentPublicSnapshot as snapshot, validateEnrollmentCsr, validateEnrollmentAuthority,
  validateEnrollmentCertificate, verifyEnrollmentSignature } from './companion-enrollment-crypto.mjs';

const FILENAME = 'enrollment.sqlite';
const VERSION = 1;
const TERMINAL = new Set(['rejected', 'cancelled', 'expired', 'revoked']);
const hash = bytes => createHash('sha256').update(bytes).digest();
const iso = value => {
  if (!Number.isSafeInteger(value) || value % 1000 || value < Date.parse('2000-01-01T00:00:00Z') || value > Date.parse('2099-12-31T23:59:59Z')) error('pairing_unavailable');
  return new Date(value).toISOString().replace('.000Z', 'Z');
};
const full = (value, regex) => typeof value === 'string' && regex.exec(value)?.[0] === value;
const id = value => full(value, /^[A-Za-z0-9_-]{1,128}$/);
const enrollmentId = value => full(value, /^enr_[A-Za-z0-9_-]{43}$/) && b64(value.slice(4), 32, 32);
function b64(value, min, max = min) {
  if (!full(value, /^[A-Za-z0-9_-]+$/) || value.length > Math.ceil(max * 4 / 3)) return null;
  const bytes = Buffer.from(value, 'base64url'); return bytes.length >= min && bytes.length <= max && bytes.toString('base64url') === value ? bytes : null;
}
function caps(value, empty = false) {
  if (!Array.isArray(value) || value.length < (empty ? 0 : 1) || value.length > 16 || value.some(x => !full(x, /^[a-z][a-z0-9-]{0,31}$/)) || new Set(value).size !== value.length) error('invalid_message');
  return [...value].sort();
}
export class EnrollmentStoreError extends Error {
  constructor(code) { super('Enrollment store request failed'); this.name = 'EnrollmentStoreError'; this.code = code; }
  [inspect.custom]() { return `EnrollmentStoreError: ${this.code}`; }
  toJSON() { return { code: this.code }; }
}
function error(code) { throw new EnrollmentStoreError(code); }

// All SQL is static. Value/row/page limits supplement, rather than pretend to be, sqlite3_limit.
const SCHEMA = [
  `CREATE TABLE meta (id INTEGER PRIMARY KEY CHECK(id=1), version INTEGER NOT NULL CHECK(version=1), material TEXT NOT NULL CHECK(length(material)<=8192), utc INTEGER NOT NULL CHECK(utc>=0 AND utc<=4102444799999), serial INTEGER NOT NULL CHECK(serial>=0 AND serial<=9007199254740991), owner INTEGER NOT NULL CHECK(owner>=0 AND owner<=9007199254740991)) STRICT`,
  `CREATE TABLE invitations (id TEXT PRIMARY KEY CHECK(length(id) BETWEEN 1 AND 128), verifier BLOB NOT NULL CHECK(length(verifier)=32), created INTEGER NOT NULL, expires INTEGER NOT NULL CHECK(expires>created), consumed INTEGER NOT NULL CHECK(consumed IN(0,1))) STRICT`,
  `CREATE TABLE enrollments (id TEXT PRIMARY KEY CHECK(length(id)=47), invitation TEXT NOT NULL UNIQUE REFERENCES invitations(id), csr BLOB NOT NULL CHECK(length(csr) BETWEEN 1 AND 4096), spki BLOB NOT NULL CHECK(length(spki)=91), keyhash BLOB NOT NULL CHECK(length(keyhash)=32), name TEXT NOT NULL CHECK(length(CAST(name AS BLOB)) BETWEEN 1 AND 128), requested TEXT NOT NULL CHECK(length(requested)<=561), granted TEXT NOT NULL CHECK(length(granted)<=561), created INTEGER NOT NULL, reservation INTEGER NOT NULL, result INTEGER NOT NULL CHECK(result=created+3600000), state TEXT NOT NULL CHECK(state IN('pending','issuing','approved','rejected','cancelled','expired','revoked')), cause TEXT CHECK(cause IN('pairing_rejected','pairing_cancelled','invitation_expired','device_revoked','credential_expired')), device TEXT CHECK(device IS NULL OR length(device)=47), generation INTEGER NOT NULL CHECK(generation BETWEEN 0 AND 2147483647), token BLOB CHECK(token IS NULL OR length(token)=32), serial INTEGER CHECK(serial IS NULL OR serial BETWEEN 1 AND 9007199254740991), before INTEGER, after INTEGER, leaf BLOB CHECK(leaf IS NULL OR length(leaf) BETWEEN 1 AND 4096)) STRICT`,
  `CREATE TABLE credentials (enrollment TEXT PRIMARY KEY REFERENCES enrollments(id), device TEXT NOT NULL UNIQUE CHECK(length(device)=47), keyhash BLOB NOT NULL CHECK(length(keyhash)=32), leafhash BLOB NOT NULL UNIQUE CHECK(length(leafhash)=32), leaf BLOB NOT NULL CHECK(length(leaf) BETWEEN 1 AND 4096), active INTEGER NOT NULL CHECK(active IN(0,1))) STRICT`,
];
const schemaNormalized = sql => sql.replace(/\s+/g, ' ').trim().replace(/;$/, '');
function metadata(input) {
  if (!input || !id(input.desktopId) || !b64(input.gatewaySpkiSha256, 32) || !b64(input.interceptionCaCertificateSha256, 32) || !b64(input.enrollmentAuthorityDer, 1, 4096)) error('pairing_unavailable');
  const supportedCapabilities = caps(input.supportedCapabilities, true), credentialLifetimeSeconds = input.credentialLifetimeSeconds ?? 3600;
  if (!Number.isInteger(credentialLifetimeSeconds) || credentialLifetimeSeconds < 60 || credentialLifetimeSeconds > 7776000) error('pairing_unavailable');
  validateEnrollmentAuthority(input.enrollmentAuthorityDer);
  return { desktopId: input.desktopId, gatewaySpkiSha256: input.gatewaySpkiSha256, enrollmentAuthorityDer: input.enrollmentAuthorityDer,
    interceptionCaCertificateSha256: input.interceptionCaCertificateSha256, supportedCapabilities, credentialLifetimeSeconds };
}
function safeDirectory(directory) {
  if (typeof directory !== 'string' || !path.isAbsolute(directory)) error('pairing_unavailable');
  const absolute = path.resolve(directory), real = fs.realpathSync(absolute);
  if (process.platform === 'win32' ? absolute.toLowerCase() !== real.toLowerCase() : absolute !== real) error('pairing_unavailable');
  let current = absolute;
  while (true) { const stat = fs.lstatSync(current); if (stat.isSymbolicLink() || !stat.isDirectory()) error('pairing_unavailable'); const parent = path.dirname(current); if (parent === current) break; current = parent; }
  const stat = fs.statSync(absolute); if (process.platform !== 'win32' && (stat.mode & 0o077)) error('pairing_unavailable');
  return path.join(real, FILENAME);
}
function regularFile(filename) { const stat = fs.lstatSync(filename); if (stat.isSymbolicLink() || !stat.isFile() || stat.nlink !== 1 || stat.size > 16 * 1024 * 1024) error('pairing_unavailable'); }

class EnrollmentStore {
  #db; #meta; #authority; #clock; #random; #closed = false; #closing = false; #unavailable = false;
  #lastUtc = -1; #lastMono = -1; #durable = 0; #anchors = new Map(); #jobs = new Map(); #handles = new WeakMap(); #attempts = [];
  constructor(options, create) {
    let db;
    try {
      this.#meta = metadata(options?.metadata); this.#authority = validateEnrollmentAuthority(this.#meta.enrollmentAuthorityDer).material();
      const origin = performance.now(); this.#clock = options.clock ?? (() => ({ utcMillis: Date.now(), monotonicMillis: Math.floor(performance.now() - origin) }));
      this.#random = options.randomBytes ?? secureRandom; const filename = safeDirectory(options.directory);
      if (create) { const fd = fs.openSync(filename, 'wx', 0o600); fs.closeSync(fd); }
      else { regularFile(filename); if (fs.statSync(filename).size === 0) error('pairing_unavailable'); }
      regularFile(filename); db = new DatabaseSync(filename, { timeout: 50, allowExtension: false, enableForeignKeyConstraints: true, enableDoubleQuotedStringLiterals: false }); this.#db = db;
      db.enableDefensive(true);
      if (create) db.exec('PRAGMA page_size=4096');
      db.exec('PRAGMA foreign_keys=ON; PRAGMA trusted_schema=OFF; PRAGMA journal_mode=DELETE; PRAGMA synchronous=EXTRA; PRAGMA locking_mode=EXCLUSIVE; PRAGMA max_page_count=4096');
      for (const [pragma, expected] of [['page_size', 4096], ['foreign_keys', 1], ['trusted_schema', 0], ['journal_mode', 'delete'], ['synchronous', 3], ['locking_mode', 'exclusive'], ['max_page_count', 4096]]) {
        if (Object.values(db.prepare(`PRAGMA ${pragma}`).get())[0] !== expected) error('pairing_unavailable');
      }
      db.exec('BEGIN EXCLUSIVE');
      if (create) { for (const sql of SCHEMA) db.exec(sql); const now = this.#observe(); db.prepare('INSERT INTO meta VALUES(1,?,?,?,0,0)').run(VERSION, JSON.stringify(this.#meta), now.utcMillis); }
      this.#validate();
      const now = this.#observe(); db.prepare('UPDATE meta SET utc=?,owner=owner+1 WHERE id=1').run(now.utcMillis); db.exec('COMMIT'); this.#durable = now.utcMillis;
      for (const row of this.#all()) this.#anchor(row, now);
      const allowed = new Set([sqlite.SQLITE_READ, sqlite.SQLITE_SELECT, sqlite.SQLITE_INSERT, sqlite.SQLITE_UPDATE, sqlite.SQLITE_DELETE, sqlite.SQLITE_TRANSACTION, sqlite.SQLITE_FUNCTION]);
      const functions = new Set(['count', 'length', 'min', 'max', 'coalesce', 'typeof']);
      db.setAuthorizer((action, first, second) => allowed.has(action) && (action !== sqlite.SQLITE_FUNCTION || functions.has(second)) ? sqlite.SQLITE_OK : sqlite.SQLITE_DENY);
    } catch { try { db?.exec('ROLLBACK'); } catch {} try { db?.close(); } catch {} error('pairing_unavailable'); }
  }
  #one(sql, ...args) { return this.#db.prepare(sql).get(...args); }
  #all() { return this.#db.prepare('SELECT * FROM enrollments').all(); }
  #validate() {
    const db = this.#db;
    const schema = db.prepare("SELECT name,sql FROM sqlite_schema WHERE type='table' AND name NOT LIKE 'sqlite_%' ORDER BY name").all();
    if (schema.length !== SCHEMA.length || schema.some(row => !SCHEMA.some(sql => schemaNormalized(sql) === schemaNormalized(row.sql))) ||
      db.prepare("SELECT count(*) AS n FROM sqlite_schema WHERE type IN('trigger','view') OR (type='index' AND sql IS NOT NULL)").get().n !== 0 ||
      db.prepare('PRAGMA integrity_check').get().integrity_check !== 'ok' || db.prepare('PRAGMA foreign_key_check').all().length ||
      db.prepare('PRAGMA page_count').get().page_count > 4096) error('pairing_unavailable');
    if (this.#one('SELECT count(*) AS n FROM meta').n !== 1 || this.#one('SELECT length(material) AS n FROM meta WHERE id=1')?.n > 8192) error('pairing_unavailable');
    const stored = this.#one('SELECT * FROM meta WHERE id=1');
    if (!stored || stored.version !== VERSION || stored.material !== JSON.stringify(this.#meta) || !Number.isSafeInteger(stored.utc) || !Number.isSafeInteger(stored.serial)) error('pairing_unavailable');
    this.#durable = stored.utc;
    for (const [table, limit] of [['invitations', 64], ['enrollments', 128], ['credentials', 256]]) if (this.#one(`SELECT count(*) AS n FROM ${table}`).n > limit) error('pairing_unavailable');
    if (this.#one('SELECT count(*) AS n FROM credentials WHERE active=1').n > 64) error('pairing_unavailable');
    // Guard every variable-size fetch, including records written by an incompatible/corrupt owner.
    if (this.#one('SELECT count(*) AS n FROM invitations WHERE length(id)>128 OR length(verifier)!=32').n ||
      this.#one('SELECT count(*) AS n FROM enrollments WHERE length(csr)>4096 OR length(spki)!=91 OR length(keyhash)!=32 OR length(CAST(name AS BLOB))>128 OR length(requested)>561 OR length(granted)>561 OR length(leaf)>4096 OR length(token)>32').n ||
      this.#one('SELECT count(*) AS n FROM credentials WHERE length(leaf)>4096 OR length(leafhash)!=32 OR length(keyhash)!=32').n) error('pairing_unavailable');
    const invitations = this.#db.prepare('SELECT * FROM invitations').all(), records = this.#all(), credentials = this.#db.prepare('SELECT * FROM credentials').all();
    for (const invite of invitations) if (!id(invite.id) || invite.created % 1000 || invite.expires !== invite.created + 300000 || ![0, 1].includes(invite.consumed)) error('pairing_unavailable');
    const serials = new Set(), devices = new Set();
    for (const row of records) {
      const invitation = invitations.find(i => i.id === row.invitation), csr = validateEnrollmentCsr(row.csr).material();
      const requested = caps(JSON.parse(row.requested)), granted = caps(JSON.parse(row.granted));
      if (!enrollmentId(row.id) || !invitation || row.reservation !== invitation.expires || row.result !== row.created + 3600000 || row.created % 1000 ||
        csr.deviceSpkiDer !== Buffer.from(row.spki).toString('base64url') || csr.deviceSpkiSha256 !== Buffer.from(row.keyhash).toString('base64url') ||
        JSON.stringify(requested) !== row.requested || JSON.stringify(granted) !== row.granted || JSON.stringify(requested.filter(x => this.#meta.supportedCapabilities.includes(x))) !== row.granted ||
        !this.#validName(row.name) || (TERMINAL.has(row.state) !== (row.cause !== null))) error('pairing_unavailable');
      if (row.generation > 0) {
        if (!full(row.device, /^dev_[A-Za-z0-9_-]{43}$/) || !b64(row.device.slice(4), 32) || devices.has(row.device) || !Number.isSafeInteger(row.serial) || row.serial < 1 || row.serial > stored.serial || serials.has(row.serial) || !Number.isSafeInteger(row.before) || !Number.isSafeInteger(row.after) || row.before >= row.after) error('pairing_unavailable');
        devices.add(row.device); serials.add(row.serial);
      } else if (row.device !== null || row.serial !== null || row.before !== null || row.after !== null || row.token !== null || row.state === 'issuing' || row.state === 'approved') error('pairing_unavailable');
      const expectedCause = { rejected: 'pairing_rejected', cancelled: 'pairing_cancelled', revoked: 'device_revoked' }[row.state];
      if ((expectedCause && row.cause !== expectedCause) || (row.state === 'expired' && row.cause !== (row.leaf === null ? 'invitation_expired' : 'credential_expired')) ||
        (row.state !== 'issuing' && row.token !== null) || (['pending', 'issuing'].includes(row.state) && row.leaf !== null)) error('pairing_unavailable');
      if (row.leaf !== null) validateEnrollmentCertificate(row.leaf, { authority: this.#meta.enrollmentAuthorityDer, deviceSpkiDer: row.spki, serial: String(row.serial), notBefore: iso(row.before), notAfter: iso(row.after) });
      const credential = credentials.find(c => c.enrollment === row.id);
      if ((row.leaf !== null) !== Boolean(credential) || (row.state === 'approved' && !credential) ||
        (credential && (credential.active !== Number(row.state === 'approved') || credential.device !== row.device || !Buffer.from(credential.leaf).equals(Buffer.from(row.leaf)) || !Buffer.from(credential.keyhash).equals(Buffer.from(row.keyhash)) || !hash(credential.leaf).equals(Buffer.from(credential.leafhash)) || invitation.consumed !== 1))) error('pairing_unavailable');
    }
    if (credentials.some(c => !records.some(r => r.id === c.enrollment)) || invitations.some(i => i.consumed && !records.some(r => r.invitation === i.id && r.leaf !== null))) error('pairing_unavailable');
    const live = records.filter(r => !TERMINAL.has(r.state)); if (new Set(live.map(r => Buffer.from(r.keyhash).toString('hex'))).size !== live.length) error('pairing_unavailable');
  }
  #observe() {
    try {
      const now = this.#clock();
      if (!now || !Number.isSafeInteger(now.utcMillis) || now.utcMillis < Date.parse('2000-01-01T00:00:00Z') || now.utcMillis > Date.parse('2099-12-31T23:59:59Z') || !Number.isSafeInteger(now.monotonicMillis) || now.monotonicMillis < 0 || now.utcMillis < Math.max(this.#durable, this.#lastUtc) || now.monotonicMillis < this.#lastMono) throw Error();
      this.#lastUtc = now.utcMillis; this.#lastMono = now.monotonicMillis; return Object.freeze({ utcMillis: now.utcMillis, monotonicMillis: now.monotonicMillis });
    } catch { this.#unavailable = true; error('pairing_unavailable'); }
  }
  #healthy() { if (this.#closed || this.#closing || this.#unavailable) error('pairing_unavailable'); return this.#observe(); }
  #sql(work) { try { return work(); } catch (caught) { if (caught instanceof EnrollmentStoreError) throw caught; this.#unavailable = true; error('pairing_unavailable'); } }
  #transaction(work) {
    return this.#sql(() => {
      this.#db.exec('BEGIN EXCLUSIVE');
      try { const now = this.#healthy(), value = work(now); this.#db.prepare('UPDATE meta SET utc=? WHERE id=1').run(this.#lastUtc); this.#db.exec('COMMIT'); this.#durable = this.#lastUtc; return value; }
      catch (caught) { try { this.#db.exec('ROLLBACK'); } catch { this.#unavailable = true; } throw caught; }
    });
  }
  #anchor(row, now) {
    const prior = this.#anchors.get(row.id);
    this.#anchors.set(row.id, { reservation: prior?.reservation ?? now.monotonicMillis + Math.max(0, row.reservation - now.utcMillis),
      result: prior?.result ?? now.monotonicMillis + Math.max(0, row.result - now.utcMillis),
      afterUtc: row.after,
      after: row.after === null ? null : prior?.afterUtc === row.after ? prior.after : now.monotonicMillis + Math.max(0, row.after - now.utcMillis) });
  }
  #due(row, field, now) { this.#anchor(row, now); return now.utcMillis >= row[field] || now.monotonicMillis >= this.#anchors.get(row.id)[field]; }
  #row(idValue) { return this.#one('SELECT * FROM enrollments WHERE id=?', idValue); }
  #expire(row, now) {
    if (row && !TERMINAL.has(row.state) && ((['pending', 'issuing'].includes(row.state) && this.#due(row, 'reservation', now)) || (row.state === 'approved' && this.#due(row, 'after', now)))) {
      this.#end(row, 'expired', row.state === 'approved' ? 'credential_expired' : 'invitation_expired'); return this.#row(row.id);
    }
    return row;
  }
  #end(row, state, cause) {
    this.#db.prepare('UPDATE enrollments SET state=?,cause=?,token=NULL WHERE id=?').run(state, cause, row.id);
    this.#db.prepare('UPDATE credentials SET active=0 WHERE enrollment=?').run(row.id);
  }
  #randomBytes() { const value = this.#random(32); if (!(value instanceof Uint8Array) || value.length !== 32) error('pairing_unavailable'); return Buffer.from(value); }
  #fresh(prefix, exists) { for (let attempt = 0; attempt < 8; attempt++) { const candidate = prefix + this.#randomBytes().toString('base64url'); if (!exists(candidate)) return candidate; } error('pairing_limit'); }
  #quota(invitation, now) {
    this.#attempts = this.#attempts.filter(a => a.at > now.monotonicMillis - 1000);
    if (this.#attempts.length >= 16 || this.#attempts.filter(a => a.invitation === invitation).length >= 4) error('pairing_limit');
    this.#attempts.push({ invitation, at: now.monotonicMillis });
  }
  #validName(value) {
    return typeof value === 'string' && Buffer.byteLength(value) >= 1 && Buffer.byteLength(value) <= 128 && !value.startsWith(' ') && !value.endsWith(' ') && !/[\u0000-\u001f\u007f-\u009f\u2028-\u202e\u2066-\u2069\ufeff\ud800-\udfff]/u.test(value);
  }
  #registered(row) { return snapshot({ protocolVersion: 1, type: 'pair_registered', desktopId: this.#meta.desktopId, invitationId: row.invitation, enrollmentId: row.id, deviceSpkiSha256: Buffer.from(row.keyhash).toString('base64url'), reservationExpiresAt: iso(row.reservation), resultExpiresAt: iso(row.result) }); }
  #result(row, now) {
    const base = { protocolVersion: 1, desktopId: this.#meta.desktopId, enrollmentId: row.id };
    if (this.#due(row, 'result', now)) return snapshot({ ...base, type: 'pair_ended', code: 'result_expired' });
    if (TERMINAL.has(row.state)) return snapshot({ ...base, type: 'pair_ended', code: row.cause });
    if (row.state !== 'approved') return snapshot({ ...base, type: 'pair_pending', reservationExpiresAt: iso(row.reservation), retryAfterMillis: 1000 });
    return snapshot({ ...base, type: 'pair_approved', deviceId: row.device, clientCertificateDer: Buffer.from(row.leaf).toString('base64url'), enrollmentAuthorityDer: this.#meta.enrollmentAuthorityDer,
      interceptionCaCertificateSha256: this.#meta.interceptionCaCertificateSha256, capabilities: JSON.parse(row.granted), credentialExpiresAt: iso(row.after), resultExpiresAt: iso(row.result) });
  }
  now() { return this.#healthy(); }
  createInvitation() {
    this.#healthy(); return this.#transaction(now => {
      this.#db.prepare('DELETE FROM invitations WHERE expires<=? AND id NOT IN(SELECT invitation FROM enrollments)').run(now.utcMillis);
      if (this.#one('SELECT count(*) AS n FROM invitations').n >= 64) error('pairing_limit');
      const invitationId = this.#fresh('inv_', x => this.#one('SELECT id FROM invitations WHERE id=?', x)), secret = this.#randomBytes(), created = Math.floor(now.utcMillis / 1000) * 1000, expires = created + 300000;
      iso(expires);
      this.#db.prepare('INSERT INTO invitations VALUES(?,?,?,?,0)').run(invitationId, hash(secret), created, expires);
      return snapshot({ invitationId, invitationSecret: secret.toString('base64url'), expiresAt: iso(expires) });
    });
  }
  reserve(pair) {
    const initial = this.#healthy();
    return this.#sql(() => {
      const invitation = this.#one('SELECT * FROM invitations WHERE id=?', typeof pair?.invitationId === 'string' ? pair.invitationId : ''), secret = b64(pair?.invitationSecret, 32);
      if (pair?.desktopId !== this.#meta.desktopId || !invitation || !secret || !timingSafeEqual(hash(secret), Buffer.from(invitation.verifier))) error('authentication_failed');
      const previous = this.#one('SELECT * FROM enrollments WHERE invitation=?', invitation.id);
      if (!previous && initial.utcMillis >= invitation.expires) error('invitation_expired');
      if (previous && this.#due(previous, 'result', initial)) error('invitation_used');
      this.#quota(invitation.id, initial);
      let csr; try { csr = validateEnrollmentCsr(pair.csrDer).material(); } catch { error('authentication_failed'); }
      const requested = caps(pair.capabilities), requestedText = JSON.stringify(requested);
      if (previous && csr.deviceSpkiSha256 !== Buffer.from(previous.keyhash).toString('base64url')) error('invitation_used');
      if (!this.#validName(pair.deviceName) || (previous && (pair.deviceName !== previous.name || requestedText !== previous.requested))) error('invalid_message');
      const granted = requested.filter(x => this.#meta.supportedCapabilities.includes(x)); if (!granted.length) error('unsupported_capability');
      if (previous) { if (this.#due(previous, 'result', this.#healthy())) error('invitation_used'); return this.#registered(previous); }
      return this.#transaction(now => {
        if (now.utcMillis >= invitation.expires) error('invitation_expired');
        for (const old of this.#all()) this.#expire(old, now);
        if (this.#one("SELECT id FROM enrollments WHERE keyhash=? AND state IN('pending','issuing','approved')", b64(csr.deviceSpkiSha256, 32))) error('invitation_used');
        if (this.#one('SELECT count(*) AS n FROM enrollments').n >= 128) error('pairing_limit');
        const eid = this.#fresh('enr_', x => this.#row(x)), created = Math.floor(now.utcMillis / 1000) * 1000;
        iso(created + 3600000);
        this.#db.prepare("INSERT INTO enrollments VALUES(?,?,?,?,?,?,?,?,?,?,?,'pending',NULL,NULL,0,NULL,NULL,NULL,NULL,NULL)").run(eid, invitation.id, b64(csr.csrDer, 1, 4096), b64(csr.deviceSpkiDer, 91), b64(csr.deviceSpkiSha256, 32), pair.deviceName, requestedText, JSON.stringify(granted), created, invitation.expires, created + 3600000);
        const row = this.#row(eid); this.#anchor(row, now); return this.#registered(row);
      });
    });
  }
  getBinding(desktopId, invitationId, eid, { requireLiveResult = false } = {}) {
    const now = this.#healthy(); return this.#sql(() => { const row = this.#row(typeof eid === 'string' ? eid : '');
      if (desktopId !== this.#meta.desktopId || !row || row.invitation !== invitationId) error('authentication_failed');
      if (requireLiveResult && this.#due(row, 'result', now)) error('authentication_failed');
      const binding = snapshot({ desktopId, gatewaySpkiSha256: this.#meta.gatewaySpkiSha256, invitationId, enrollmentId: eid, deviceSpkiDer: Buffer.from(row.spki).toString('base64url'), deviceSpkiSha256: Buffer.from(row.keyhash).toString('base64url'), reservationExpiresAt: iso(row.reservation), resultExpiresAt: iso(row.result) });
      return Object.freeze({ ...binding, observedAt: () => ({ ...now }) });
    });
  }
  verifyProof(eid, payload, signature) {
    const now = this.#healthy(); return this.#sql(() => { const row = this.#row(typeof eid === 'string' ? eid : ''); if (!row) return false; this.#quota(row.invitation, now); return verifyEnrollmentSignature(row.spki, payload, signature); });
  }
  beginApproval(eid) {
    this.#healthy(); const result = this.#transaction(now => {
      let row = this.#row(typeof eid === 'string' ? eid : ''); if (!row) error('authentication_failed'); row = this.#expire(row, now);
      if (this.#due(row, 'result', now) || TERMINAL.has(row.state)) return { error: row.cause === 'invitation_expired' ? 'invitation_expired' : 'invitation_used' };
      if (row.state === 'approved') return { kind: 'approved', result: this.#result(row, now) };
      if (this.#jobs.has(eid) || this.#jobs.size >= 4) error('pairing_limit');
      const currentSerial = this.#one('SELECT serial FROM meta WHERE id=1').serial;
      if (currentSerial >= Number.MAX_SAFE_INTEGER || row.generation >= 2147483647) error('pairing_limit');
      const device = row.device ?? this.#fresh('dev_', x => this.#one('SELECT id FROM enrollments WHERE device=?', x)), token = this.#randomBytes(), serial = currentSerial + 1, t = Math.floor(now.utcMillis / 1000) * 1000;
      const before = Math.max(Date.parse(this.#authority.notBefore), t - 300000), after = Math.min(Date.parse(this.#authority.notAfter), t + this.#meta.credentialLifetimeSeconds * 1000);
      if (after < t + 60000 || t < Date.parse(this.#authority.notBefore)) error('pairing_unavailable');
      this.#db.prepare('UPDATE meta SET serial=? WHERE id=1').run(serial);
      this.#db.prepare("UPDATE enrollments SET state='issuing',device=?,generation=generation+1,token=?,serial=?,before=?,after=? WHERE id=?").run(device, token, serial, before, after, eid);
      row = this.#row(eid);
      const job = snapshot({ desktopId: this.#meta.desktopId, invitationId: row.invitation, enrollmentId: eid, deviceId: device, generation: row.generation, token: token.toString('base64url'), serial: String(serial), deviceSpkiDer: Buffer.from(row.spki).toString('base64url'), deviceSpkiSha256: Buffer.from(row.keyhash).toString('base64url'), csrDer: Buffer.from(row.csr).toString('base64url'), capabilities: JSON.parse(row.granted), notBefore: iso(before), notAfter: iso(after), subject: 'CN=HTTP FreeKit device', profile: 'p256-client-auth-v1' });
      return { kind: 'job', job };
    });
    if (result.error) error(result.error);
    if (result.kind === 'job') { const material = result.job.material(); this.#jobs.set(eid, result.job); this.#handles.set(result.job, { material, settled: false }); }
    return Object.freeze(result);
  }
  #handle(job) { const handle = job && typeof job === 'object' ? this.#handles.get(job) : null; if (!handle) error('authentication_failed'); return handle; }
  #settle(job, handle) { handle.settled = true; if (this.#jobs.get(handle.material.enrollmentId) === job) this.#jobs.delete(handle.material.enrollmentId); }
  publish(job, candidate) {
    const handle = this.#handle(job); if (handle.settled) error('authentication_failed');
    try {
      this.#healthy(); const expected = handle.material; let leaf;
      try { leaf = validateEnrollmentCertificate(candidate, { authority: this.#meta.enrollmentAuthorityDer, deviceSpkiDer: expected.deviceSpkiDer, serial: expected.serial, notBefore: expected.notBefore, notAfter: expected.notAfter }).material(); } catch { error('authentication_failed'); }
      return this.#transaction(now => {
        let row = this.#row(expected.enrollmentId); row = this.#expire(row, now);
        if (!row || row.state !== 'issuing' || row.generation !== expected.generation || row.token === null || !timingSafeEqual(Buffer.from(row.token), b64(expected.token, 32)) || this.#due(row, 'reservation', now) || now.utcMillis < row.before || now.utcMillis >= row.after) error('authentication_failed');
        if (this.#one('SELECT count(*) AS n FROM credentials').n >= 256 || this.#one('SELECT count(*) AS n FROM credentials WHERE active=1').n >= 64) error('pairing_limit');
        const raw = b64(leaf.certificateDer, 1, 4096);
        this.#db.prepare("UPDATE enrollments SET state='approved',token=NULL,leaf=? WHERE id=?").run(raw, row.id);
        this.#db.prepare('INSERT INTO credentials VALUES(?,?,?,?,?,1)').run(row.id, row.device, row.keyhash, hash(raw), raw);
        this.#db.prepare('UPDATE invitations SET consumed=1 WHERE id=?').run(row.invitation);
        row = this.#row(row.id); this.#anchor(row, now); return this.#result(row, now);
      });
    } finally { this.#settle(job, handle); }
  }
  abandon(job) {
    const handle = this.#handle(job); if (handle.settled) return;
    try {
      if (!this.#closed && !this.#unavailable) this.#sql(() => {
        this.#db.exec('BEGIN EXCLUSIVE');
        try { this.#db.prepare('UPDATE enrollments SET token=NULL WHERE id=? AND generation=? AND token=?').run(handle.material.enrollmentId, handle.material.generation, b64(handle.material.token, 32)); this.#db.prepare('UPDATE meta SET utc=? WHERE id=1').run(this.#lastUtc); this.#db.exec('COMMIT'); this.#durable = this.#lastUtc; }
        catch (caught) { try { this.#db.exec('ROLLBACK'); } catch {} throw caught; }
      });
    } finally { this.#settle(job, handle); }
  }
  #decision(eid, state, cause) {
    this.#healthy(); return this.#transaction(now => {
      let row = this.#row(typeof eid === 'string' ? eid : ''); if (!row) error('authentication_failed'); row = this.#expire(row, now);
      if ((state === 'revoked' || !this.#due(row, 'result', now)) && !TERMINAL.has(row.state)) { this.#end(row, state, cause); row = this.#row(row.id); }
      return this.#result(row, now);
    });
  }
  reject(eid) { return this.#decision(eid, 'rejected', 'pairing_rejected'); }
  cancel(eid) { return this.#decision(eid, 'cancelled', 'pairing_cancelled'); }
  revoke(eid) { return this.#decision(eid, 'revoked', 'device_revoked'); }
  readResult(eid) {
    this.#healthy(); return this.#transaction(now => { const row = this.#row(typeof eid === 'string' ? eid : ''); if (!row) error('authentication_failed'); return this.#result(this.#expire(row, now), now); });
  }
  authorizeCertificate(candidate) {
    const now = this.#healthy(); return this.#sql(() => {
      let raw; if (candidate instanceof Uint8Array) raw = candidate.length <= 4096 ? Buffer.from(candidate) : null; else raw = b64(candidate, 1, 4096); if (!raw || !raw.length) return null;
      const credential = this.#one('SELECT * FROM credentials WHERE leafhash=? AND active=1', hash(raw)); if (!credential || !Buffer.from(credential.leaf).equals(raw)) return null;
      const row = this.#row(credential.enrollment);
      if (!row || row.state !== 'approved' || now.utcMillis < row.before || this.#due(row, 'after', now)) return null;
      try { validateEnrollmentCertificate(raw, { authority: this.#meta.enrollmentAuthorityDer, deviceSpkiDer: row.spki, serial: String(row.serial), notBefore: iso(row.before), notAfter: iso(row.after), utcMillis: now.utcMillis }); } catch { this.#unavailable = true; error('pairing_unavailable'); }
      return snapshot({ desktopId: this.#meta.desktopId, deviceId: row.device, enrollmentId: row.id, clientCertificateSha256: hash(raw).toString('base64url'), deviceSpkiSha256: Buffer.from(row.keyhash).toString('base64url'), credentialExpiresAt: iso(row.after) });
    });
  }
  close() {
    if (this.#closed) return; this.#closing = true;
    if (this.#jobs.size) error('pairing_unavailable');
    try { this.#db.close(); this.#closed = true; } catch { this.#unavailable = true; error('pairing_unavailable'); }
  }
  toJSON() { return '[Enrollment store]'; }
  toString() { return '[Enrollment store]'; }
  [inspect.custom]() { return '[Enrollment store]'; }
}
export function createEnrollmentStore(options) { return new EnrollmentStore(options, true); }
export function openEnrollmentStore(options) { return new EnrollmentStore(options, false); }
