import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import tls from 'node:tls';
import { once } from 'node:events';
import { X509Certificate, createPrivateKey, createPublicKey } from 'node:crypto';
import { inspect } from 'node:util';
import { createReferenceInterceptionAssets } from './reference-interception-assets.mjs';
import { ReferenceInterceptionError, referenceInterceptionProfile as profile } from './reference-interception-contract.mjs';

const directory = () => fs.mkdtempSync(path.join(os.tmpdir(), 'reference-assets-'));
const finite = (error, code, joined = true) => {
  assert.ok(error instanceof ReferenceInterceptionError);
  assert.equal(error.code, code); assert.equal(error.joined, joined);
  assert.equal(JSON.stringify(error), JSON.stringify({ code, joined }));
  assert.doesNotMatch(inspect(error), /CANARY|BEGIN|\/tmp\//);
  return true;
};

async function fixture(t) {
  const dir = directory();
  let assets;
  try { assets = await createReferenceInterceptionAssets({ directory: dir }); }
  catch (error) { if (error.joined) fs.rmSync(dir, { recursive: true }); throw error; }
  t.after(async () => {
    const snapshot = await assets.close();
    assert.equal(snapshot.commandsStarted, snapshot.commandsClosed);
    assert.equal(snapshot.commandsStarted, snapshot.processGroupsClosed);
    fs.rmSync(dir, { recursive: true });
  });
  return { assets, dir };
}

async function handshake(assets, role, trust, hostname = profile.hostname) {
  const sockets = new Set();
  const server = tls.createServer(assets.tlsOptions(role), socket => { socket.end(); });
  server.on('connection', socket => { sockets.add(socket); socket.once('close', () => sockets.delete(socket)); });
  server.on('tlsClientError', () => {});
  server.listen(0, '127.0.0.1');
  await once(server, 'listening');
  const client = tls.connect({ host: '127.0.0.1', port: server.address().port, servername: hostname,
    ca: assets.caPem(trust), rejectUnauthorized: true, ALPNProtocols: ['http/1.1'], minVersion: 'TLSv1.2', maxVersion: 'TLSv1.3' });
  client.setTimeout(5000, () => client.destroy(Error('test_deadline')));
  let result;
  try {
    result = await new Promise(resolve => {
      client.once('secureConnect', () => resolve({ authorized: client.authorized, protocol: client.alpnProtocol }));
      client.once('error', error => resolve({ code: error.code }));
    });
  } finally {
    const closed = new Promise(resolve => client.once('close', resolve));
    client.destroy(); await closed;
    const joined = [...sockets].map(socket => new Promise(resolve => { socket.once('close', resolve); socket.destroy(); }));
    const stopped = new Promise((resolve, reject) => server.close(error => error ? reject(error) : resolve()));
    await Promise.all([...joined, stopped]);
  }
  return result;
}

test('separate bounded P256 chains, exact constraints, scoped real TLS and joined commands', async t => {
  const { assets, dir } = await fixture(t);
  assert.deepEqual(assets.snapshot(), { commandsStarted: 8, commandsClosed: 8, processGroupsClosed: 8, closed: false });
  const authorities = [];
  for (const role of ['interception', 'origin']) {
    const pem = assets.caPem(role), der = assets.caDer(role), ca = new X509Certificate(der);
    const options = assets.tlsOptions(role), leaf = new X509Certificate(options.cert), key = createPrivateKey(options.key);
    authorities.push(ca);
    assert.ok(der.length < 4096 && options.cert.length < 8192 && options.key.length < 4096);
    assert.deepEqual(ca.raw, der); assert.equal(ca.toString(), pem.toString());
    assert.equal(ca.ca, true); assert.equal(ca.subject, ca.issuer); assert.ok(ca.verify(ca.publicKey));
    assert.equal(leaf.ca, false); assert.ok(leaf.verify(ca.publicKey)); assert.ok(leaf.checkPrivateKey(key));
    assert.equal(ca.publicKey.asymmetricKeyDetails.namedCurve, 'prime256v1');
    assert.equal(leaf.publicKey.asymmetricKeyDetails.namedCurve, 'prime256v1');
    assert.equal(leaf.subjectAltName, `DNS:${profile.hostname}`);
    assert.deepEqual(leaf.keyUsage, ['1.3.6.1.5.5.7.3.1']);
    for (const cert of [ca, leaf]) {
      assert.ok(Date.parse(cert.validFrom) <= Date.now()); assert.ok(Date.parse(cert.validTo) > Date.now());
      assert.ok(Date.parse(cert.validTo) - Date.parse(cert.validFrom) <= 86400000);
    }
    // DER extension encodings include exact pathlen 0, CA=false, and KU bits.
    assert.ok(ca.raw.includes(Buffer.from('0603551d130101ff040830060101ff020100', 'hex')));
    assert.ok(ca.raw.includes(Buffer.from('0603551d0f0101ff040403020106', 'hex')));
    assert.ok(leaf.raw.includes(Buffer.from('0603551d130101ff04023000', 'hex')));
    assert.ok(leaf.raw.includes(Buffer.from('0603551d0f0101ff040403020780', 'hex')));
    assert.equal(options.minVersion, 'TLSv1.2'); assert.equal(options.maxVersion, 'TLSv1.3');
    assert.deepEqual(options.ALPNProtocols, ['http/1.1']); assert.equal(options.handshakeTimeout, 5000);
    assert.deepEqual(await handshake(assets, role, role), { authorized: true, protocol: 'http/1.1' });
    const wrongCa = await handshake(assets, role, role === 'origin' ? 'interception' : 'origin');
    assert.ok(['UNABLE_TO_VERIFY_LEAF_SIGNATURE', 'UNABLE_TO_GET_ISSUER_CERT_LOCALLY', 'CERT_SIGNATURE_FAILURE'].includes(wrongCa.code), wrongCa.code);
    assert.equal((await handshake(assets, role, role, 'wrong.invalid')).code, 'ERR_TLS_CERT_ALTNAME_INVALID');
  }
  assert.notDeepEqual(authorities[0].raw, authorities[1].raw);
  assert.equal(authorities[0].verify(authorities[1].publicKey), false);
  assert.equal(fs.statSync(dir).mode & 0o777, 0o700);
  for (const name of fs.readdirSync(dir)) assert.equal(fs.statSync(path.join(dir, name)).mode & 0o777, 0o600);
});

test('defensive material, exact roles, redaction and idempotent denial after close', async t => {
  const { assets, dir } = await fixture(t);
  const expected = assets.caDer('origin'), pem = assets.caPem('origin'), options = assets.tlsOptions('origin');
  assets.caDer('origin').fill(0); assets.caPem('origin').fill(0);
  const changed = assets.tlsOptions('origin'); changed.key.fill(0); changed.cert.fill(0); changed.ALPNProtocols.push('h2');
  assert.deepEqual(assets.caDer('origin'), expected); assert.deepEqual(assets.caPem('origin'), pem);
  assert.deepEqual(assets.tlsOptions('origin'), options);
  const snapshot = assets.snapshot(); snapshot.commandsStarted = -1; assert.equal(assets.snapshot().commandsStarted, 8);
  for (const role of [undefined, null, {}, ['origin'], 'Origin', 'origin\n', 'toString', new String('origin')]) {
    for (const method of ['caDer', 'caPem', 'tlsOptions']) assert.throws(() => assets[method](role), error => finite(error, 'configuration'));
  }
  for (const text of [JSON.stringify(assets), inspect(assets), String(assets)]) {
    assert.doesNotMatch(text, /BEGIN|PRIVATE|reference-target|key|pem|der|sha|\/tmp\//i);
    assert.ok(!text.includes(dir));
  }
  const [first, second] = await Promise.all([assets.close(), assets.close()]);
  assert.deepEqual(first, second); assert.equal(first.closed, true);
  for (const method of ['caDer', 'caPem', 'tlsOptions']) assert.throws(() => assets[method]('origin'), error => finite(error, 'assets_unavailable'));
  // Caller-owned TLS option copies are not silently overwritten by assets.close().
  assert.ok(options.key.includes(Buffer.from('PRIVATE KEY')));
  options.key.fill(0);
});

test('invalid directories and executable configuration start no commands and never clean caller data', async () => {
  const root = directory(), empty = path.join(root, 'empty'); fs.mkdirSync(empty, { mode: 0o700 });
  const nonempty = path.join(root, 'nonempty'); fs.mkdirSync(nonempty, { mode: 0o700 }); fs.writeFileSync(path.join(nonempty, 'CANARY'), 'keep');
  const publicDir = path.join(root, 'public'); fs.mkdirSync(publicDir, { mode: 0o755 });
  const link = path.join(root, 'link'); fs.symlinkSync(empty, link);
  try {
    for (const dir of [undefined, '', '.', 'relative', link, nonempty, publicDir, root + '/missing', empty + '/..', link + '/.']) {
      await assert.rejects(createReferenceInterceptionAssets({ directory: dir }), error => finite(error, 'configuration'));
    }
    for (const openssl of ['', null, {}, 'CANARY\nprivate']) await assert.rejects(createReferenceInterceptionAssets({ directory: empty, openssl }), error => finite(error, 'configuration'));
    assert.deepEqual(fs.readdirSync(empty), []); assert.equal(fs.readFileSync(path.join(nonempty, 'CANARY'), 'utf8'), 'keep');
  } finally { fs.rmSync(root, { recursive: true }); }
});

test('unsafe writable or foreign-owned sticky ancestors are rejected before any provider invocation', async t => {
  for (const { mode, foreign } of [{ mode: 0o777 }, { mode: 0o770 }, { mode: 0o1777, foreign: true }]) {
    await t.test(mode.toString(8), { skip: foreign && process.geteuid?.() !== 0 }, async () => {
      const root = directory(), parent = path.join(root, 'parent'), work = path.join(parent, 'nested', 'work');
      fs.mkdirSync(work, { recursive: true, mode: 0o700 }); fs.chmodSync(parent, mode);
      if (foreign) fs.chownSync(parent, 65534, 65534);
      const marker = path.join(root, 'invoked'), provider = path.join(root, 'provider');
      fs.writeFileSync(provider, `#!${process.execPath}\nrequire('node:fs').writeFileSync(${JSON.stringify(marker)},'invoked');require('node:child_process').execFileSync('openssl',process.argv.slice(2),{stdio:'ignore'});`, { mode: 0o700 });
      let assets, failure, joined = false;
      try {
        try { assets = await createReferenceInterceptionAssets({ directory: work, openssl: provider }); }
        catch (error) { failure = error; joined = error.joined === true; }
        if (assets) { await assets.close(); joined = true; }
        assert.equal(fs.existsSync(marker), false, 'unsafe ancestor must fail before provider starts');
        assert.deepEqual(fs.readdirSync(work), []);
        finite(failure, 'configuration');
      } finally { if (joined) fs.rmSync(root, { recursive: true }); }
    });
  }
});

test('all four CA and leaf identities must be cryptographically distinct even across PEM encodings', async t => {
  const names = ['interception-ca-key.pem', 'interception-key.pem', 'origin-ca-key.pem', 'origin-key.pem'];
  for (let first = 0; first < names.length; first++) for (let second = first + 1; second < names.length; second++) {
    await t.test(`${first}-${second}`, async () => {
      const root = directory(), work = path.join(root, 'work'), provider = path.join(root, 'provider'), pids = path.join(root, 'pids');
      fs.mkdirSync(work, { mode: 0o700 });
      fs.writeFileSync(provider, `#!${process.execPath}
const fs=require('node:fs'),{execFileSync}=require('node:child_process'),{createPrivateKey}=require('node:crypto');
fs.appendFileSync(${JSON.stringify(pids)},String(process.pid)+'\\n');
const args=process.argv.slice(2),source=${JSON.stringify(names[first])},target=${JSON.stringify(names[second])};
const duplicate=args[0]==='req' && args[args.indexOf('-keyout')+1]===target;
if(duplicate) {
  for(const flag of ['-newkey','-pkeyopt','-keyout']) { const at=args.indexOf(flag); if(at!==-1) args.splice(at,2); }
  args.push('-key',source);
}
if(args[0]==='verify') process.exit(0); // A malicious provider can lie about verification.
try { execFileSync('openssl',args,{stdio:'ignore'}); } catch { process.exit(1); }
if(duplicate) fs.writeFileSync(target,createPrivateKey(fs.readFileSync(source)).export({format:'pem',type:'sec1'}));
`, { mode: 0o700 });
      let assets, failure, joined = false;
      try {
        try { assets = await createReferenceInterceptionAssets({ directory: work, openssl: provider }); }
        catch (error) { failure = error; joined = error.joined === true; }
        if (assets) { await assets.close(); joined = true; }
        const actualPids = fs.readFileSync(pids, 'utf8').trim().split('\n').map(Number);
        assert.equal(actualPids.length, 8, 'all provider commands succeeded before identity rejection');
        for (const pid of actualPids) {
          assert.throws(() => process.kill(pid, 0), { code: 'ESRCH' });
          assert.throws(() => process.kill(-pid, 0), { code: 'ESRCH' });
        }
        assert.equal(fs.readFileSync(path.join(work, names[first])).equals(fs.readFileSync(path.join(work, names[second]))), false);
        const source = createPublicKey(createPrivateKey(fs.readFileSync(path.join(work, names[first]))));
        const target = createPublicKey(createPrivateKey(fs.readFileSync(path.join(work, names[second]))));
        assert.equal(source.export({ format: 'der', type: 'spki' }).equals(target.export({ format: 'der', type: 'spki' })), true);
        finite(failure, 'assets_unavailable');
      } finally { if (joined) fs.rmSync(root, { recursive: true }); }
    });
  }
});

async function failingProvider(t, script) {
  const root = directory(), work = path.join(root, 'work'), provider = path.join(root, 'provider');
  fs.mkdirSync(work, { mode: 0o700 }); fs.writeFileSync(provider, `#!${process.execPath}\n${script}`, { mode: 0o700 });
  let joined = false;
  t.after(() => { if (joined) fs.rmSync(root, { recursive: true }); });
  const started = performance.now();
  await assert.rejects(createReferenceInterceptionAssets({ directory: work, openssl: provider }), error => {
    finite(error, 'assets_unavailable'); joined = error.joined; return true;
  });
  assert.ok(performance.now() - started < 15000);
  const pid = Number(fs.readFileSync(path.join(root, 'pid'), 'utf8'));
  assert.throws(() => process.kill(pid, 0), { code: 'ESRCH' });
  assert.throws(() => process.kill(-pid, 0), { code: 'ESRCH' });
}

test('bounded provider exit failure redacts output and actually joins its child/group', async t => {
  await failingProvider(t, `require('node:fs').writeFileSync(require('node:path').join(__dirname,'pid'),String(process.pid));process.stderr.write('CANARY_PRIVATE_PROVIDER');process.exit(7);`);
});

test('provider timeout really terminates and joins an ignoring child/group', async t => {
  await failingProvider(t, `require('node:fs').writeFileSync(require('node:path').join(__dirname,'pid'),String(process.pid));process.on('SIGTERM',()=>{});setInterval(()=>{},1000);`);
});

test('provider output bound terminates and joins without publishing private output', async t => {
  await failingProvider(t, `require('node:fs').writeFileSync(require('node:path').join(__dirname,'pid'),String(process.pid));process.stdout.write('CANARY'.repeat(10000));setInterval(()=>{},1000);`);
});

test('zero-exit providers cannot smuggle trailing DER, wrong keys or altered constraints', async t => {
  for (const mutation of ['trailing', 'key', 'constraints']) {
    await t.test(mutation, async () => {
      const root = directory(), work = path.join(root, 'work'), provider = path.join(root, 'provider');
      fs.mkdirSync(work, { mode: 0o700 });
      const script = `#!${process.execPath}
const fs=require('node:fs'),{execFileSync}=require('node:child_process');
const args=process.argv.slice(2),mutation=${JSON.stringify(mutation)};
if(mutation==='constraints' && args[0]==='x509') {
  const name=args[args.indexOf('-extfile')+1];
  fs.writeFileSync(name,fs.readFileSync(name,'utf8').replace('digitalSignature','digitalSignature,keyEncipherment'));
}
try { execFileSync('openssl',args,{stdio:'ignore'}); } catch { process.exit(1); }
if(args[0]==='verify') {
  if(mutation==='key') fs.copyFileSync('interception-ca-key.pem','interception-key.pem');
  if(mutation==='trailing') {
    const {X509Certificate}=require('node:crypto');
    const raw=Buffer.concat([new X509Certificate(fs.readFileSync('interception-cert.pem')).raw,Buffer.from([0])]);
    fs.writeFileSync('interception-cert.pem','-----BEGIN CERTIFICATE-----\\n'+raw.toString('base64').match(/.{1,64}/g).join('\\n')+'\\n-----END CERTIFICATE-----\\n');
  }
}
`;
      fs.writeFileSync(provider, script, { mode: 0o700 });
      let joined = false;
      try {
        await assert.rejects(createReferenceInterceptionAssets({ directory: work, openssl: provider }), error => {
          joined = error.joined; return finite(error, 'assets_unavailable');
        });
      } finally { if (joined) fs.rmSync(root, { recursive: true }); }
    });
  }
});

test('missing command has observed spawn close and joined group', async () => {
  const dir = directory(); let joined = false;
  try { await assert.rejects(createReferenceInterceptionAssets({ directory: dir, openssl: path.join(dir, 'missing-CANARY') }), error => { joined = error.joined; return finite(error, 'assets_unavailable'); }); }
  finally { if (joined) fs.rmSync(dir, { recursive: true }); }
});
