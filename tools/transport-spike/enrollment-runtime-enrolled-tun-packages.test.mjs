import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { createEnrolledTunPackageOwner } from './enrolled-tun-packages.mjs';

const interop = 'com.httpfreekit.interop.test', runtime = 'com.httpfreekit.capturetest', traffic = 'com.httpfreekit.capturetraffic';
const control = runtime + '.permission.CONTROL_TRAFFIC';
const pass = output => ({ code: 0, signal: null, reason: null, closeObserved: true, processGroupClosed: true, stderrBytes: 0, output });
const rejected = () => ({ ...pass('PRIVATE_PROVIDER'), code: 1 });
const dump = grant => `Packages:\n  Package [${interop}] (12abc):\n    requested permissions:\n      ${control}\n    install permissions:\n      ${control}: granted=${grant}\n    User 0: installed=true\n`;
const deferred = () => { let resolve; const promise = new Promise(done => { resolve = done; }); return { promise, resolve }; };

function fixture(t, options = {}) {
  const savedSdk = process.env.ANDROID_HOME;
  process.env.ANDROID_HOME = path.resolve('build/c5-fake-sdk');
  t.after(() => { if (savedSdk === undefined) delete process.env.ANDROID_HOME; else process.env.ANDROID_HOME = savedSdk; });
  const file = value => String(value).replaceAll('\\', '/');
  t.mock.method(fs, 'statSync', () => ({ size: options.metadataSize ?? 100, isFile: () => options.regularMetadata !== false }));
  t.mock.method(fs, 'readFileSync', value => {
    const name = file(value).includes('/android/build/') ? interop : file(value).includes('/runtime/build/') ? runtime : traffic;
    return Buffer.from(JSON.stringify({ applicationId: options.badMetadata ? 'PRIVATE_CANARY' : name,
      elements: [{ outputFile: options.outputFile ?? 'fixture.apk' }] }));
  });
  const calls = [], installed = new Set(options.preexisting ?? []), foreign = new Set();
  let signatures = 0;
  const host = {
    state: async () => 'device',
    async command(executable, args, timeout) {
      calls.push({ executable, args, timeout });
      if (args.join(' ').includes('--print-certs')) {
        signatures++;
        const hash = options.mismatch && signatures === 3 ? 'b'.repeat(64) : 'a'.repeat(64);
        return pass(`Signer #1 certificate SHA-256 digest: ${hash}\n` + (options.multisigner ? `Signer #2 certificate SHA-256 digest: ${hash}\n` : ''));
      }
      return options.buildFails ? rejected() : pass('Build complete ✓\n');
    },
    async adb(args, timeout, extras, cleanup) {
      calls.push({ args, timeout, extras, cleanup });
      if (args.slice(0, 4).join(' ') === 'shell pm list packages') {
        if (options.probeFails) return rejected();
        return pass(installed.has(args[4]) || foreign.has(args[4]) ? 'package:' + args[4] + '\n' : '');
      }
      if (args[0] === 'install') {
        const name = file(args[2]).includes('/runtime/build/') ? runtime : traffic;
        installed.add(name);
        if (options.installGate) await options.installGate.promise;
        if (options.unjoinedInstall === name) return { ...pass('Success\n'), closeObserved: false, processGroupClosed: false };
        return options.installFails === name ? rejected() : pass('Performing Streamed Install\nSuccess\n');
      }
      if (args.slice(0, 3).join(' ') === 'shell dumpsys package') return pass(options.dump ?? dump(true));
      if (args.slice(0, 3).join(' ') === 'shell pm grant') return options.grantFails === args[4] ? rejected() : pass('');
      if (args.slice(0, 3).join(' ') === 'shell am force-stop') return options.stopFails === args[3] ? rejected() : pass('');
      if (args[0] === 'uninstall') {
        if (options.cleanupGate) await options.cleanupGate.promise;
        if (options.uninstallFails === args[1]) return rejected();
        installed.delete(args[1]);
        if (options.replaceAfterUninstall === args[1]) foreign.add(args[1]);
        return pass('Success\n');
      }
      if (args.slice(0, 4).join(' ') === 'shell -T sh -c') {
        if (options.processPresent || [...installed, ...foreign].some(name => args[4].includes('pidof ' + name + ' '))) return rejected();
        return pass('TUN_PACKAGE_ABSENT\n');
      }
      throw Error('Unexpected fake command');
    },
  };
  return { owner: createEnrolledTunPackageOwner(host), calls, installed, options };
}

test('API26 verifies all three APK signers and actual control grant, installs owner before traffic and cleans both', async t => {
  const f = fixture(t), s = await f.owner.prepare(26);
  assert.deepEqual(Object.keys(s), ['sameSigner', 'controlTrafficGranted', 'packages', 'permissions']);
  assert(s.sameSigner && s.controlTrafficGranted);
  assert.deepEqual(s.permissions, { mode: 'not_required', interopLocalNetwork: null, trafficLocalNetwork: null, interopNotification: null });
  assert.deepEqual(s.packages.map(x => x.package), [runtime, traffic]);
  assert(s.packages.every(x => x.initiallyAbsent && x.installAttempted && x.installed));
  const installs = f.calls.filter(x => x.args[0] === 'install');
  assert(installs[0].args[2].replaceAll('\\', '/').includes('/runtime/'));
  assert(installs[1].args[2].replaceAll('\\', '/').includes('/traffic/'));
  assert.equal(f.calls.filter(x => x.args.includes('--print-certs') || x.args.join(' ').includes('--print-certs')).length, 3);
  s.packages[0].installed = false; assert.equal(f.owner.snapshot().packages[0].installed, true);
  const closed = await f.owner.cleanup();
  assert.equal(closed.failed, false);
  assert(closed.snapshot.packages.every(x => x.uninstallConfirmed && x.absentAfterCleanup));
  assert(!f.calls.some(x => x.args[0] === 'uninstall' && x.args[1] === interop));
  const before = f.calls.length; await f.owner.cleanup(); assert.equal(f.calls.length, before);
});

test('API37 grants only the fixed three runtime permissions after signature control authorization', async t => {
  const f = fixture(t), s = await f.owner.prepare(37);
  const grants = f.calls.filter(x => x.args.slice(0, 3).join(' ') === 'shell pm grant');
  assert.deepEqual(grants.map(x => x.args.slice(3)), [[interop, 'android.permission.ACCESS_LOCAL_NETWORK'],
    [traffic, 'android.permission.ACCESS_LOCAL_NETWORK'], [interop, 'android.permission.POST_NOTIFICATIONS']]);
  assert.equal(s.permissions.mode, 'owned_ci_grant');
  assert(Object.values(s.permissions).slice(1).every(x => x.exitCode === 0));
  assert.equal((await f.owner.cleanup()).failed, false);
});

test('unsupported APIs refuse before any build, grant or device mutation', async t => {
  const f = fixture(t);
  for (const api of [25, 27, 36, '26', null]) await assert.rejects(f.owner.prepare(api), /enrollment_fixture_failed/);
  assert.equal(f.calls.length, 0); assert.equal((await f.owner.cleanup()).failed, false);
});

for (const [name, options] of [['different signer', { mismatch: true }], ['multiple signers', { multisigner: true }],
  ['bad metadata package', { badMetadata: true }], ['metadata path injection', { outputFile: '../PRIVATE.apk' }],
  ['oversized metadata', { metadataSize: 65537 }], ['build failure', { buildFails: true }]]) {
  test(name + ' refuses without installing or deleting any package', async t => {
    const f = fixture(t, options);
    await assert.rejects(f.owner.prepare(26), error => error.message === 'enrollment_fixture_failed' && !String(error).includes('PRIVATE'));
    assert(!f.calls.some(x => x.args[0] === 'install'));
    await f.owner.cleanup(); assert(!f.calls.some(x => x.args[0] === 'uninstall'));
  });
}

test('either pre-existing extra is refused before either installation and is never stopped or uninstalled', async t => {
  const f = fixture(t, { preexisting: [traffic] });
  await assert.rejects(f.owner.prepare(26)); await f.owner.cleanup();
  assert(!f.calls.some(x => x.args[0] === 'install' || x.args[0] === 'uninstall' || x.args.includes('force-stop')));
  assert(f.installed.has(traffic));
});

for (const [name, value] of [['denied', dump(false)],
  ['requested only', dump(true).replace('    install permissions:', '    requested permissions:')],
  ['foreign package', dump(true).replace(interop, runtime)],
  ['duplicate grant', dump(true).replace('    User 0:', `      ${control}: granted=true\n    User 0:`)]]) {
  test('control permission ' + name + ' cannot substitute for an actual exact-package install grant', async t => {
    const f = fixture(t, { dump: value });
    await assert.rejects(f.owner.prepare(26));
    assert.equal(f.owner.snapshot().controlTrafficGranted, false);
    assert(!f.calls.some(x => x.args.includes('grant')));
    assert.equal((await f.owner.cleanup()).failed, false);
  });
}

test('a failed runtime permission grant cannot pass and both installed extras still clean up', async t => {
  const f = fixture(t, { grantFails: 'android.permission.ACCESS_LOCAL_NETWORK' });
  await assert.rejects(f.owner.prepare(37));
  assert.equal(f.owner.snapshot().permissions.interopLocalNetwork.exitCode, 1);
  assert.equal(f.owner.snapshot().permissions.trafficLocalNetwork, null);
  assert.equal((await f.owner.cleanup()).failed, false);
});

test('partial install failure remains owned and cleanup attempts every admitted package', async t => {
  const f = fixture(t, { installFails: traffic });
  await assert.rejects(f.owner.prepare(26));
  assert(f.owner.snapshot().packages.every(x => x.installAttempted));
  assert.equal(f.owner.snapshot().packages[1].installed, false);
  const result = await f.owner.cleanup(); assert.equal(result.failed, false);
  assert(result.snapshot.packages.every(x => x.uninstallConfirmed && x.absentAfterCleanup));
});

test('an unjoined installer cannot turn a temporary package absence into complete cleanup', async t => {
  const f = fixture(t, { unjoinedInstall: runtime });
  await assert.rejects(f.owner.prepare(26));
  const before = f.calls.length;
  await assert.rejects(f.owner.prepare(26)); assert.equal(f.calls.length, before);
  const result = await f.owner.cleanup();
  assert.equal(result.failed, true);
  assert.equal(result.snapshot.packages[0].uninstallConfirmed, true);
  assert.equal(result.snapshot.packages[0].absentAfterCleanup, false);
  assert.equal(result.snapshot.packages[1].installAttempted, false);
});

test('stop and uninstall failures do not skip the other package or erase cleanup failure', async t => {
  const f = fixture(t); await f.owner.prepare(26);
  f.options.stopFails = runtime; f.options.uninstallFails = traffic;
  const failed = await f.owner.cleanup(); assert.equal(failed.failed, true);
  assert(failed.snapshot.packages[0].absentAfterCleanup); assert(!failed.snapshot.packages[1].absentAfterCleanup);
  assert.equal(f.calls.filter(x => x.args.includes('force-stop')).length, 2);
  assert.equal(f.calls.filter(x => x.args[0] === 'uninstall').length, 2);
  f.options.stopFails = null; f.options.uninstallFails = null;
  const retried = await f.owner.cleanup(); assert.equal(retried.failed, true);
  assert(retried.snapshot.packages.every(x => x.absentAfterCleanup));
});

test('successful uninstall releases ownership even when a replacement prevents absence verification', async t => {
  const f = fixture(t); await f.owner.prepare(26);
  f.options.replaceAfterUninstall = runtime;
  assert.equal((await f.owner.cleanup()).failed, true);
  const before = f.calls.filter(x => x.args[0] === 'uninstall' || x.args.includes('force-stop')).length;
  assert.equal((await f.owner.cleanup()).failed, true);
  assert.equal(f.calls.filter(x => x.args[0] === 'uninstall' || x.args.includes('force-stop')).length, before);
});

test('package absence does not substitute for actual process absence', async t => {
  const f = fixture(t); await f.owner.prepare(26); f.options.processPresent = true;
  const result = await f.owner.cleanup();
  assert.equal(result.failed, true);
  assert(result.snapshot.packages.every(x => x.uninstallConfirmed && !x.absentAfterCleanup));
});

test('concurrent cleanup is serialized and waits for an admitted installation before uninstalling', async t => {
  const installGate = deferred(), f = fixture(t, { installGate });
  const preparing = f.owner.prepare(26); const rejectedPrepare = assert.rejects(preparing);
  while (!f.calls.some(x => x.args[0] === 'install')) await new Promise(resolve => setImmediate(resolve));
  const first = f.owner.cleanup(), second = f.owner.cleanup();
  assert(!f.calls.some(x => x.args[0] === 'uninstall'));
  installGate.resolve(); await rejectedPrepare;
  const results = await Promise.all([first, second]);
  assert(results.every(x => x.failed === false));
  assert.equal(f.calls.filter(x => x.args[0] === 'uninstall').length, 1);
  assert.equal(f.owner.snapshot().packages[1].installAttempted, false);
});
