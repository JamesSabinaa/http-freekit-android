import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { spawnSync } from 'node:child_process';

// Execute the actual workflow function with a private fake ADB; never set any host/device clock here.
const workflow = fs.readFileSync(new URL('../../.github/workflows/enrollment-runtime.yml', import.meta.url), 'utf8').replace(/\r\n/g, '\n');
const block = /          # BEGIN A22 FRESH AVD CLOCK ALIGNMENT\n([\s\S]*?)          # END A22 FRESH AVD CLOCK ALIGNMENT/.exec(workflow);
assert.ok(block, 'The actual clock-alignment function must be covered');
const alignment = block[1].replace(/^ {10}/gm, '');
const bash = process.platform === 'win32' ? 'C:/Program Files/Git/bin/bash.exe' : '/bin/bash';
const order = ['root', 'root_wait', 'root_identity', 'disable_auto', 'auto_read', 'setter', 'unroot', 'shell_wait', 'shell_identity'];
const adb = String.raw`#!/usr/bin/env bash
set -eu
mode=shell
if [[ -f "$TEST_STATE" ]]; then mode="$(cat "$TEST_STATE")"; fi
case "$3" in
  root) step=root; mode=root ;;
  unroot) step=unroot; mode=shell ;;
  wait-for-device) if [[ "$mode" == root ]]; then step=root_wait; else step=shell_wait; fi ;;
  shell)
    if [[ "$4 $5" == 'id -u' ]]; then
      if [[ "$mode" == root ]]; then step=root_identity; else step=shell_identity; fi
    elif (( $# == 8 )) && [[ "$4 $5 $6 $7 $8" == 'settings put global auto_time 0' ]]; then step=disable_auto
    elif [[ "$4 $5 $6 $7" == 'settings get global auto_time' ]]; then step=auto_read
    elif [[ "$4 $5 $6" == '/system/bin/toybox date -u' && "$7" =~ ^@[0-9]{10}\.[0-9]{9}$ ]]; then
      step=setter; printf '%s\n' "$7" > "$TEST_SETTER"
    else exit 98; fi ;;
  *) exit 99 ;;
esac
printf '%s\n' "$step" >> "$TEST_LOG"
if [[ "$step" == root || "$step" == unroot ]]; then
  printf '%s\n' "$mode" > "$TEST_STATE"
  transition="$TEST_ROOT_MODE"
  if [[ "$step" == unroot ]]; then transition="$TEST_RESTORE_MODE"; fi
  case "$transition" in nonzero_verified|nonzero_unverified) exit 9 ;; esac
fi
if [[ "$step" == root_wait && "$TEST_ROOT_MODE" == shared_deadline ]] ||
   [[ "$step" == shell_wait && "$TEST_RESTORE_MODE" == shared_deadline ]]; then sleep 29; fi
if [[ "$step" == root_identity || "$step" == shell_identity ]]; then
  identity_mode="$TEST_ROOT_MODE"; wanted=0; previous=2000
  if [[ "$step" == shell_identity ]]; then identity_mode="$TEST_RESTORE_MODE"; wanted=2000; previous=0; fi
  case "$identity_mode" in
    unknown) echo unknown; exit 0 ;;
    other_uid) echo 1000; exit 0 ;;
    empty) exit 0 ;;
    read_failure) exit 9 ;;
    nonzero_unverified) echo "$previous"; exit 0 ;;
    previous_once) if [[ ! -f "$TEST_STATE.$step" ]]; then touch "$TEST_STATE.$step"; echo "$previous"; exit 0; fi ;;
    shared_deadline) sleep 5 ;;
    crlf) printf '%s\r\n' "$wanted"; exit 0 ;;
  esac
fi
if [[ "$step" == "$TEST_FAIL_AT" ]]; then
  case "$step" in root_identity) echo 2000; exit 0 ;; shell_identity) echo 0; exit 0 ;; auto_read) echo 1; exit 0 ;; *) exit 9 ;; esac
fi
printf '%s\n' "$mode" > "$TEST_STATE"
case "$step" in root_identity) echo 0 ;; shell_identity) echo 2000 ;; auto_read) echo 0 ;; esac
`;
function execute(failAt = '', badHostTime = false, rootMode = '', restoreMode = '') {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'freekit-a22-clock-'));
  try {
    fs.writeFileSync(path.join(directory, 'adb'), adb, { mode: 0o700 });
    fs.writeFileSync(path.join(directory, 'date'), '#!/usr/bin/env bash\nif [[ "$TEST_BAD_HOST_TIME" == 1 ]]; then printf \'1792879320.123456789;false\\n\'; else exec /usr/bin/date "$@"; fi\n', { mode: 0o700 });
    const setup = 'set -euo pipefail\n' +
      'if command -v cygpath >/dev/null 2>&1; then test_bin="$(cygpath -u "$TEST_DIRECTORY")"; else test_bin="$TEST_DIRECTORY"; fi\n' +
      'export PATH="$test_bin:$PATH"\nexport TEST_LOG="$test_bin/order" TEST_STATE="$test_bin/state" TEST_SETTER="$test_bin/setter"\n';
    const result = spawnSync(bash, ['-c', setup + alignment + '\nalign_enrollment_clock\nprintf "DRIVER_CAN_START\\n"\n'], {
      cwd: directory, encoding: 'utf8', timeout: 45000, windowsHide: true,
      env: { ...process.env, TEST_DIRECTORY: directory, TEST_FAIL_AT: failAt, TEST_BAD_HOST_TIME: badHostTime ? '1' : '0',
        TEST_ROOT_MODE: rootMode, TEST_RESTORE_MODE: restoreMode },
    });
    assert.equal(result.error, undefined);
    const observed = fs.existsSync(path.join(directory, 'order')) ? fs.readFileSync(path.join(directory, 'order'), 'utf8').trim().split('\n') : [];
    const setter = fs.existsSync(path.join(directory, 'setter')) ? fs.readFileSync(path.join(directory, 'setter'), 'utf8').trim() : null;
    assert.equal(observed.filter(step => step === 'root').length, 1, 'never retry root');
    assert.ok(observed.filter(step => step === 'unroot').length <= 1, 'never retry unroot');
    return { status: result.status, stdout: result.stdout, stderr: result.stderr, observed, setter };
  } finally {
    assert.equal(path.dirname(path.resolve(directory)), path.resolve(os.tmpdir()));
    assert.match(path.basename(directory), /^freekit-a22-clock-/);
    fs.rmSync(directory, { recursive: true, force: true });
  }
}
test('actual workflow alignment uses API26-compatible UTC positional epoch before restoring shell and driver admission', () => {
  const result = execute(); assert.equal(result.status, 0, result.stderr); assert.deepEqual(result.observed, order);
  assert.match(result.setter, /^@[0-9]{10}\.[0-9]{9}$/); assert.match(result.stdout, /ordinary ADB shell restored/); assert.match(result.stdout, /DRIVER_CAN_START/);
});
for (const step of order.filter(step => !['root', 'unroot'].includes(step))) test(`clock setup refuses ${step} failure or incorrect readback before driver starts`, () => {
  const result = execute(step); assert.equal(result.status, ['root_identity', 'shell_identity', 'auto_read'].includes(step) ? 1 : 9, result.stderr);
  if (['root_identity', 'shell_identity'].includes(step)) {
    const position = order.indexOf(step);
    assert.deepEqual(result.observed.slice(0, position), order.slice(0, position));
    assert.ok(result.observed.length > position + 1 && result.observed.slice(position).every(value => value === step));
  } else assert.deepEqual(result.observed, order.slice(0, order.indexOf(step) + 1));
  assert.doesNotMatch(result.stdout, /DRIVER_CAN_START|alignment completed/);
});
for (const transition of ['root', 'unroot']) {
  const run = mode => execute('', false, transition === 'root' ? mode : '', transition === 'unroot' ? mode : '');
  const identity = transition === 'root' ? 'root_identity' : 'shell_identity';
  test(`nonzero ${transition} transport status is diagnostic only after exact resulting UID verification`, () => {
    const result = run('nonzero_verified');
    assert.equal(result.status, 0, result.stderr); assert.deepEqual(result.observed, order);
    assert.match(result.stdout, new RegExp(`Enrollment ADB ${transition} transition exit: 9`));
    assert.match(result.stdout, /DRIVER_CAN_START/);
  });
  test(`transitional ${transition} UID is polled without repeating the transition command`, () => {
    const result = run('previous_once'), position = order.indexOf(identity);
    assert.equal(result.status, 0, result.stderr);
    assert.deepEqual(result.observed, [...order.slice(0, position), identity, ...order.slice(position)]);
    assert.match(result.stdout, /DRIVER_CAN_START/);
  });
  test(`exact ${transition} UID readback accepts ADB CRLF`, () => {
    const result = run('crlf'); assert.equal(result.status, 0, result.stderr); assert.deepEqual(result.observed, order);
  });
  for (const mode of ['unknown', 'other_uid', 'empty', 'read_failure', 'nonzero_unverified']) {
    test(`${transition} ${mode} identity fails before driver admission`, () => {
      const result = run(mode), position = order.indexOf(identity);
      assert.equal(result.status, mode === 'read_failure' ? 9 : 1, result.stderr);
      assert.deepEqual(result.observed.slice(0, position), order.slice(0, position));
      assert.ok(result.observed.slice(position).every(step => step === identity));
      assert.doesNotMatch(result.stdout, /DRIVER_CAN_START|alignment completed/);
      if (transition === 'root') assert.equal(result.setter, null);
    });
  }
  test(`${transition} reconnect and identity read share the same thirty-second deadline`, () => {
    const began = performance.now(), result = run('shared_deadline'), elapsed = performance.now() - began;
    assert.equal(result.status, 124, result.stderr);
    assert.deepEqual(result.observed, order.slice(0, order.indexOf(identity) + 1));
    assert.ok(elapsed >= 29000 && elapsed < 34000, `elapsed ${elapsed}`);
    assert.doesNotMatch(result.stdout, /DRIVER_CAN_START|alignment completed/);
    if (transition === 'root') assert.equal(result.setter, null);
  });
}

test('noncanonical host time never reaches the remote date setter or driver', () => {
  const result = execute('', true); assert.equal(result.status, 1); assert.deepEqual(result.observed, order.slice(0, 5));
  assert.equal(result.setter, null); assert.doesNotMatch(result.stdout, /DRIVER_CAN_START|alignment completed/);
});
