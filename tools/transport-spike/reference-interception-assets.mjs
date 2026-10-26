// Owned host-only research identities. No trust-store or global TLS changes.
import fs from 'node:fs';
import path from 'node:path';
import { createPrivateKey, createPublicKey, X509Certificate } from 'node:crypto';
import { inspect } from 'node:util';
import { runDraftCommand } from './draft-stream-command.mjs';
import { referenceInterceptionProfile as profile, ReferenceInterceptionError } from './reference-interception-contract.mjs';

const roles = ['interception', 'origin'];
const fail = (code = 'assets_unavailable', joined = true) => { throw new ReferenceInterceptionError(code, joined); };

function privateDirectory(directory) {
  if (typeof directory !== 'string' || !path.isAbsolute(directory) || path.resolve(directory) !== directory || fs.realpathSync(directory) !== directory) fail('configuration');
  if (typeof process.geteuid !== 'function') fail('configuration');
  const uid = process.geteuid();
  for (let current = directory;; current = path.dirname(current)) {
    const stat = fs.lstatSync(current);
    // A trusted owner must control every path component. Writable shared
    // ancestors are safe only with sticky deletion protection (e.g. /tmp).
    if (!stat.isDirectory() || stat.isSymbolicLink() || ![0, uid].includes(stat.uid) ||
        (stat.mode & 0o022) && !(stat.mode & 0o1000)) fail('configuration');
    if (path.dirname(current) === current) break;
  }
  const stat = fs.statSync(directory);
  if ((stat.mode & 0o777) !== 0o700 || stat.uid !== uid || fs.readdirSync(directory).length) fail('configuration');
}

// Strict, bounded DER tree, including extension payloads. Reject BER lengths,
// nonminimal primitives, unordered SETs and trailing bytes before provider use.
function der(bytes) {
  let count = 0;
  function read(start, limit, depth) {
    if (++count > 512 || depth > 16 || start + 2 > limit) fail();
    let at = start;
    const tag = bytes[at++];
    if (!tag || (tag & 31) === 31) fail();
    let length = bytes[at++];
    if (length & 128) {
      const size = length & 127;
      if (!size || size > 2 || at + size > limit || bytes[at] === 0) fail();
      length = 0;
      for (let i = 0; i < size; i++) length = length * 256 + bytes[at++];
      if (length < 128) fail();
    }
    const content = bytes.subarray(at, at + length), end = at + length, children = [];
    if (end > limit) fail();
    if (tag & 32) {
      let previous;
      while (at < end) {
        const child = read(at, end, depth + 1);
        const encoded = bytes.subarray(at, child.end);
        if (tag === 49 && previous && Buffer.compare(previous, encoded) > 0) fail();
        previous = encoded; children.push(child); at = child.end;
      }
    } else {
      if (tag === 1 && (length !== 1 || ![0, 255].includes(content[0]))) fail();
      if (tag === 2 && (!length || length > 1 && (content[0] === 0 && !(content[1] & 128) || content[0] === 255 && content[1] & 128))) fail();
      if (tag === 3 && (!length || content[0] > 7 || length === 1 && content[0] !== 0 || content.at(-1) & ((1 << content[0]) - 1))) fail();
      if (tag === 5 && length) fail();
      if (tag === 6 && (!length || content.at(-1) & 128 || content.some((v, i) => v === 128 && (i === 0 || !(content[i - 1] & 128))))) fail();
      if (tag === 12) new TextDecoder('utf-8', { fatal: true }).decode(content);
      if (tag === 19 && !/^[A-Za-z0-9 '()+,\-./:=?]*$/.test(content.toString('latin1'))) fail();
      if (tag === 22 && content.some(v => v > 127)) fail();
      if (tag === 23 && !/^\d{12}Z$/.test(content.toString('ascii'))) fail();
      if (tag === 24 && !/^\d{14}Z$/.test(content.toString('ascii'))) fail();
    }
    return { tag, content, children, end };
  }
  const root = read(0, bytes.length, 0);
  if (root.end !== bytes.length) fail();
  return root;
}

function certificate(pem, keyBytes, authority, ca) {
  const cert = new X509Certificate(pem);
  if (!Buffer.from(cert.toString()).equals(pem) || cert.raw.length > 4096) fail();
  const tree = der(cert.raw), key = createPrivateKey(keyBytes), now = Date.now();
  if (tree.tag !== 48 || tree.children.length !== 3 || key.asymmetricKeyType !== 'ec' || key.asymmetricKeyDetails?.namedCurve !== 'prime256v1' ||
      !cert.checkPrivateKey(key) || !createPublicKey(key).export({ type: 'spki', format: 'der' }).equals(cert.publicKey.export({ type: 'spki', format: 'der' })) ||
      cert.ca !== ca || !(Date.parse(cert.validFrom) <= now && now < Date.parse(cert.validTo)) ||
      Date.parse(cert.validTo) - Date.parse(cert.validFrom) > 86400000 ||
      !cert.checkIssued(authority ?? cert) || !cert.verify((authority ?? cert).publicKey)) fail();
  const extensions = tree.children[0]?.children.filter(node => node.tag === 163);
  if (extensions.length !== 1 || extensions[0].children.length !== 1) fail();
  const values = new Map();
  for (const ext of extensions[0].children[0].children) {
    const [oid, second, third] = ext.children;
    if (ext.tag !== 48 || oid?.tag !== 6 || !second || ext.children.length !== (second.tag === 1 ? 3 : 2)) fail();
    const id = oid.content.toString('hex'), critical = second.tag === 1;
    const value = critical ? third : second;
    if (values.has(id) || value?.tag !== 4 || critical && second.content[0] !== 255) fail();
    // All generated extension values are single canonical DER values.
    const encoded = value.content;
    der(encoded);
    if (!['551d13', '551d0f', '551d25', '551d11', '551d0e', '551d23'].includes(id)) fail();
    values.set(id, { critical, encoded });
  }
  const exact = (id, critical, hex) => {
    const value = values.get(id);
    if (!value || value.critical !== critical || value.encoded.toString('hex') !== hex) fail();
  };
  exact('551d13', true, ca ? '30060101ff020100' : '3000');
  exact('551d0f', true, ca ? '03020106' : '03020780');
  if (ca) {
    if (cert.subject !== cert.issuer || values.has('551d11') || values.has('551d25')) fail();
  } else {
    exact('551d25', false, '300a06082b06010505070301');
    const hostname = Buffer.from(profile.hostname, 'ascii');
    exact('551d11', false, Buffer.concat([Buffer.from([48, hostname.length + 2, 130, hostname.length]), hostname]).toString('hex'));
    if (cert.subjectAltName !== `DNS:${profile.hostname}` || cert.checkHost(profile.hostname, { subject: 'never', wildcards: false }) !== profile.hostname ||
        cert.keyUsage?.length !== 1 || cert.keyUsage[0] !== '1.3.6.1.5.5.7.3.1') fail();
  }
  return cert;
}

class Assets {
  #material; #counts; #closed = false;
  constructor(material, counts) { this.#material = material; this.#counts = counts; }
  #get(role) {
    if (!roles.some(value => role === value)) fail('configuration');
    if (this.#closed) fail();
    return this.#material.get(role);
  }
  caDer(role) { return Buffer.from(this.#get(role).der); }
  caPem(role) { return Buffer.from(this.#get(role).pem); }
  tlsOptions(role) {
    const material = this.#get(role);
    return { key: Buffer.from(material.key), cert: Buffer.from(material.cert), minVersion: 'TLSv1.2', maxVersion: 'TLSv1.3',
      ALPNProtocols: ['http/1.1'], handshakeTimeout: profile.timeoutMillis };
  }
  snapshot() { return { ...this.#counts, closed: this.#closed }; }
  async close() {
    if (!this.#closed) {
      this.#closed = true;
      for (const material of this.#material.values()) for (const buffer of Object.values(material)) buffer.fill(0);
      this.#material.clear();
    }
    return this.snapshot();
  }
  toJSON() { return this.snapshot(); }
  toString() { return '[Reference interception assets]'; }
  [inspect.custom]() { return this.snapshot(); }
}

export async function createReferenceInterceptionAssets({ directory, openssl = 'openssl' } = {}) {
  const counts = { commandsStarted: 0, commandsClosed: 0, processGroupsClosed: 0 }, material = new Map();
  let pending = false;
  const joined = () => !pending && counts.commandsStarted === counts.commandsClosed && counts.commandsStarted === counts.processGroupsClosed;
  const write = (name, bytes = '') => fs.writeFileSync(path.join(directory, name), bytes, { flag: 'wx', mode: 0o600 });
  const read = name => {
    const filename = path.join(directory, name), stat = fs.lstatSync(filename);
    if (!stat.isFile() || stat.isSymbolicLink() || stat.nlink !== 1 || stat.uid !== process.geteuid() || (stat.mode & 0o777) !== 0o600 || stat.size < 1 || stat.size > 8192) fail();
    return fs.readFileSync(filename);
  };
  const command = async args => {
    pending = true; counts.commandsStarted++;
    const result = await runDraftCommand(openssl, args, { cwd: directory, timeoutMillis: profile.timeoutMillis, maxOutputBytes: 16384 });
    if (result.closeObserved) counts.commandsClosed++;
    if (result.processGroupClosed) counts.processGroupsClosed++;
    pending = false;
    if (!joined()) fail('cleanup_unjoined', false);
    if (result.reason || result.code !== 0) fail();
  };
  try {
    if (typeof openssl !== 'string' || !openssl || openssl.length > 4096 || /[\0\r\n]/.test(openssl)) fail('configuration');
    try { privateDirectory(directory); } catch { fail('configuration'); }
    write('request.cnf', '[req]\ndistinguished_name=subject\nprompt=no\n[subject]\nCN=Reference research\n');
    for (const role of roles) {
      for (const suffix of ['ca-key.pem', 'ca.pem', 'key.pem', 'request.pem', 'cert.pem']) write(`${role}-${suffix}`);
      write(`${role}-leaf.cnf`, `basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature\nextendedKeyUsage=serverAuth\nsubjectAltName=DNS:${profile.hostname}\n`);
      await command(['req', '-config', 'request.cnf', '-new', '-x509', '-newkey', 'ec', '-pkeyopt', 'ec_paramgen_curve:P-256', '-nodes', '-sha256', '-days', '1', '-subj', `/CN=Reference ${role} CA`, '-addext', 'basicConstraints=critical,CA:TRUE,pathlen:0', '-addext', 'keyUsage=critical,keyCertSign,cRLSign', '-keyout', `${role}-ca-key.pem`, '-out', `${role}-ca.pem`]);
      await command(['req', '-config', 'request.cnf', '-new', '-newkey', 'ec', '-pkeyopt', 'ec_paramgen_curve:P-256', '-nodes', '-sha256', '-subj', `/CN=${profile.hostname}`, '-keyout', `${role}-key.pem`, '-out', `${role}-request.pem`]);
      await command(['x509', '-req', '-in', `${role}-request.pem`, '-CA', `${role}-ca.pem`, '-CAkey', `${role}-ca-key.pem`, '-set_serial', '2', '-days', '1', '-sha256', '-extfile', `${role}-leaf.cnf`, '-out', `${role}-cert.pem`]);
      await command(['verify', '-x509_strict', '-purpose', 'sslserver', '-verify_hostname', profile.hostname, '-CAfile', `${role}-ca.pem`, `${role}-cert.pem`]);
      const buffers = [];
      let caKey;
      try {
        const caPem = read(`${role}-ca.pem`); buffers.push(caPem);
        caKey = read(`${role}-ca-key.pem`); buffers.push(caKey);
        const key = read(`${role}-key.pem`); buffers.push(key);
        const cert = read(`${role}-cert.pem`); buffers.push(cert);
        const authority = certificate(caPem, caKey, null, true);
        certificate(cert, key, authority, false);
        material.set(role, { pem: caPem, der: Buffer.from(authority.raw), key, cert });
      } catch (error) { for (const buffer of buffers) buffer.fill(0); throw error; }
      finally { caKey?.fill(0); }
    }
    const identities = [];
    for (const value of material.values()) {
      for (const encoded of [value.der, value.cert]) {
        const spki = new X509Certificate(encoded).publicKey.export({ type: 'spki', format: 'der' });
        if (identities.some(previous => previous.equals(spki))) fail();
        identities.push(spki);
      }
    }
    return new Assets(material, counts);
  } catch (error) {
    for (const value of material.values()) for (const buffer of Object.values(value)) buffer.fill(0);
    if (!joined()) fail('cleanup_unjoined', false);
    if (error instanceof ReferenceInterceptionError) throw error;
    fail();
  }
}
