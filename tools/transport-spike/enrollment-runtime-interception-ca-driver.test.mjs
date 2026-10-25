import test from 'node:test';
import assert from 'node:assert/strict';
import { ownedCaPermissionDeclared, ownedCaPermissionGranted } from './run-interception-ca-runtime.mjs';
import { enrollmentRuntimeOptions } from './run-enrollment-runtime.mjs';
import { createInterceptionCaInvocationParser } from './interception-ca-runtime-results.mjs';
import { interceptionCaRuntimeMethod } from './interception-ca-runtime-descriptor.mjs';

const permission = 'android.permission.ACCESS_LOCAL_NETWORK';
test('installed self-instrumentation package needs an exact requested permission, not a grant or foreign entry', () => {
  const good = `Packages:\n  Package [com.httpfreekit.interop.test] (abc123):\n    requested permissions:\n      android.permission.INTERNET\n      ${permission}\n    install permissions:\n      android.permission.INTERNET: granted=true\n`;
  assert.equal(ownedCaPermissionDeclared(good), true);
  assert.equal(ownedCaPermissionDeclared(good.replace('com.httpfreekit.interop.test', 'com.httpfreekit.interop')), false);
  assert.equal(ownedCaPermissionDeclared(`Packages:\n  Package [com.httpfreekit.interop.test] (abc123):\n    requested permissions:\n      android.permission.INTERNET\n  Package [com.example.other] (def456):\n    requested permissions:\n      ${permission}\n`), false);
  assert.equal(ownedCaPermissionDeclared(`Packages:\n  Package [com.example.other] (def456):\n    requested permissions:\n      ${permission}\n  Package [com.httpfreekit.interop.test] (abc123):\n    requested permissions:\n      android.permission.INTERNET\n`), false);
  assert.equal(ownedCaPermissionDeclared(good + good), false);
  for (const bad of [`requested permissions:\n      android.permission.INTERNET\n    install permissions:\n      ${permission}: granted=true`,
    `requested permissions:\n      ${permission}_EXTRA\n`, `requested permissions:\n      ${permission}: granted=true\n`,
    'requested permissions:\n      android.permission.INTERNET\n', Buffer.alloc(262145, 65).toString(), null])
    assert.equal(ownedCaPermissionDeclared(bad), false);
});
test('API 37 reads an actual User 0 runtime grant from only the owned installed package', () => {
  const owned = `Package [com.httpfreekit.interop.test] (abc123):\n    requested permissions:\n      ${permission}\n`;
  const granted = `${owned}    install permissions:\n      android.permission.INTERNET: granted=true\n  User 0: installed=true\n    runtime permissions:\n      ${permission}: granted=true, flags=[ USER_SET ]\n`;
  assert.equal(ownedCaPermissionGranted(granted), true);
  assert.equal(ownedCaPermissionGranted(granted.replace('User 0: installed=true', 'User 0: installed=false hidden=true')), false);
  assert.equal(ownedCaPermissionGranted(granted.replace('User 0: installed=true', 'User 0: hidden=false')), false);
  assert.equal(ownedCaPermissionGranted(granted.replace('User 0: installed=true', 'User 0: installed=true installed=false')), false);
  assert.equal(ownedCaPermissionGranted(granted + `    runtime permissions:\n      ${permission}: granted=false\n`), false);
  assert.equal(ownedCaPermissionGranted(granted + `      ${permission}: granted=false\n`), false);
  assert.equal(ownedCaPermissionGranted(granted + `      ${permission}: granted=unknown\n`), false);
  assert.equal(ownedCaPermissionGranted(granted.replace('granted=true, flags=', 'granted=false, flags=')), false);
  assert.equal(ownedCaPermissionGranted(granted.replace('User 0:', 'User 10:')), false);
  assert.equal(ownedCaPermissionGranted(granted.replace('runtime permissions:', 'install permissions:')), false);
  assert.equal(ownedCaPermissionGranted(granted.replace('com.httpfreekit.interop.test', 'com.example.other')), false);
  assert.equal(ownedCaPermissionGranted(granted + '  User 0: installed=true\n    runtime permissions:\n      android.permission.INTERNET: granted=true\n'), false);
  assert.equal(ownedCaPermissionGranted(`${owned}  User 0: installed=true\n    runtime permissions:\n      ${permission}: granted=false\n  User 10: installed=true\n    runtime permissions:\n      ${permission}: granted=true\n`), false);
  assert.equal(ownedCaPermissionGranted(`${owned}  User 0: installed=true\n    runtime permissions:\n      android.permission.INTERNET: granted=true\nPackage [com.example.other] (def456):\n  User 0: installed=true\n    runtime permissions:\n      ${permission}: granted=true\n`), false);
});
test('A23 CLI accepts no desktop checkout or accidental fallback to A22a', () => {
  assert.equal(enrollmentRuntimeOptions(['--serial', 'emulator-5554']).suite, 'a22a');
  assert.equal(enrollmentRuntimeOptions(['--serial', 'emulator-5554', '--suite', 'a23']).suite, 'a23');
  for (const key of ['--desktop-root', '--desktop-commit']) assert.throws(() => enrollmentRuntimeOptions([
    '--serial', 'emulator-5554', '--suite', 'a23', key, key === '--desktop-root' ? '/tmp/desktop' : 'a'.repeat(40)]), /invalid_enrollment_arguments/);
});
test('new CA parser remains method-scoped and cannot call approval from an incomplete phase', () => {
  let observed = 0;
  const parser = createInterceptionCaInvocationParser(() => { observed++; });
  parser.push(Buffer.from('INSTRUMENTATION_STATUS: class=com.httpfreekit.interop.DraftInterceptionCaInteropTest\n' +
    `INSTRUMENTATION_STATUS: test=${interceptionCaRuntimeMethod}\nINSTRUMENTATION_STATUS: numtests=1\nINSTRUMENTATION_STATUS_CODE: 1\n` +
    'INSTRUMENTATION_STATUS: draftCaVersion=1\nINSTRUMENTATION_STATUS: draftCaPhase=saved-key-approval-validated'));
  assert.equal(observed, 0);
  const result = parser.finish();
  assert.equal(result.state, 'incomplete'); assert.equal(observed, 0);
});
