import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { spawnSync } from 'node:child_process';

const workflow = fs.readFileSync(new URL('../../.github/workflows/capture-runtime.yml', import.meta.url), 'utf8').replace(/\r\n/g, '\n');
const extract = name => {
  const found = new RegExp(`          # BEGIN C1 ${name}\\n([\\s\\S]*?)          # END C1 ${name}`).exec(workflow);
  assert.ok(found); return found[1].replace(/^ {10}/gm, '');
};
const cleanup = extract('OWNED EMULATOR CLEANUP'), alignment = extract('FRESH AVD CLOCK ALIGNMENT');
const bash = process.platform === 'win32' ? 'C:/Program Files/Git/bin/bash.exe' : '/bin/bash';
const setup = 'set -euo pipefail\nif command -v cygpath >/dev/null 2>&1; then test_bin="$(cygpath -u "$TEST_DIRECTORY")"; node_bin="$(cygpath -u "$TEST_NODE_DIRECTORY")"; else test_bin="$TEST_DIRECTORY"; node_bin="$TEST_NODE_DIRECTORY"; fi\nexport PATH="$test_bin:$node_bin:$PATH"\n';
const temporary = operation => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'freekit-capture-check-'));
  try { return operation(directory); }
  finally {
    assert.equal(path.dirname(path.resolve(directory)), path.resolve(os.tmpdir()));
    assert.match(path.basename(directory), /^freekit-capture-check-/);
    fs.rmSync(directory, { recursive: true, force: true });
  }
};

for (const viaTrap of [false, true]) for (const status of [0, 7, 124]) {
  test(`actual capture workflow ${viaTrap ? 'EXIT' : 'explicit'} cleanup preserves ${status} and joins the owned emulator substitute`, () => temporary(directory => {
    fs.writeFileSync(path.join(directory, 'adb'), '#!/usr/bin/env bash\nif [[ "$TEST_STATUS" == 0 ]]; then kill "$TEST_EMULATOR_PID"; exit 0; fi\nexit 9\n', { mode: 0o700 });
    const child = '(printf READY > "$test_bin/ready"; exec sleep 30) &\nemulator_pid=$!\nexport TEST_EMULATOR_PID="$emulator_pid"\n' +
      'deadline=$((SECONDS+5)); while [[ ! -f "$test_bin/ready" ]]; do if ((SECONDS>=deadline)); then kill "$emulator_pid"; wait "$emulator_pid" || true; exit 88; fi; sleep 0.01; done\ndriver_status="$TEST_STATUS"\n';
    const end = viaTrap ? 'trap \'status=$?; if cleanup "$status"; then exit 0; else exit $?; fi\' EXIT\nexit "$TEST_STATUS"\n' : 'if cleanup "$TEST_STATUS"; then exit 0; else exit $?; fi\n';
    const result = spawnSync(bash, ['-c', setup + child + cleanup + end], { cwd: directory, encoding: 'utf8', timeout: 15000, windowsHide: true,
      env: { ...process.env, TEST_DIRECTORY: directory, TEST_NODE_DIRECTORY: path.dirname(process.execPath), TEST_STATUS: String(status), GITHUB_SHA: 'a'.repeat(40), API_LEVEL: '26' } });
    assert.equal(result.error, undefined); assert.equal(result.status, status, result.stderr);
    const report = JSON.parse(fs.readFileSync(path.join(directory, 'build/reports/capture-runtime/host-cleanup.json'), 'utf8'));
    assert.equal(report.driverExitCode, status); assert.equal(report.stopExitCode, status === 0 ? 0 : 9);
    assert.equal(report.terminationObserved, true); assert.equal(report.joinObserved, true); assert.notEqual(report.emulatorExitCode, 127);
    assert.equal(report.format, 'http-freekit-capture-host-cleanup');
  }));
}

const order = ['root', 'root_wait', 'root_identity', 'disable_auto', 'auto_read', 'setter', 'unroot', 'shell_wait', 'shell_identity'];
const fakeAdb = `#!/usr/bin/env bash
set -eu
mode=shell; if [[ -f "$TEST_STATE" ]]; then mode="$(cat "$TEST_STATE")"; fi
case "$3" in
 root) step=root; mode=root ;;
 unroot) step=unroot; mode=shell ;;
 wait-for-device) if [[ "$mode" == root ]]; then step=root_wait; else step=shell_wait; fi ;;
 shell)
  if [[ "$4 $5" == 'id -u' ]]; then if [[ "$mode" == root ]]; then step=root_identity; else step=shell_identity; fi
  elif (( $# == 8 )) && [[ "$4 $5 $6 $7 $8" == 'settings put global auto_time 0' ]]; then step=disable_auto
  elif [[ "$4 $5 $6 $7" == 'settings get global auto_time' ]]; then step=auto_read
  elif [[ "$4 $5 $6" == '/system/bin/toybox date -u' && "$7" =~ ^@[0-9]{10}\\.[0-9]{9}$ ]]; then step=setter
  else exit 98; fi ;;
 *) exit 99 ;;
esac
printf '%s\\n' "$step" >> "$TEST_LOG"
if [[ "$step" == root ]]; then
 printf '%s\\n' "$mode" > "$TEST_STATE"
 case "$TEST_ROOT_MODE" in nonzero_verified|nonzero_unverified) exit 9 ;; esac
fi
if [[ "$step" == root_identity ]]; then
 case "$TEST_ROOT_MODE" in
  unknown) echo unknown; exit 0 ;;
  read_failure) exit 9 ;;
  nonzero_unverified) echo 2000; exit 0 ;;
  shell_once) if [[ ! -f "$TEST_STATE.root-transitional" ]]; then touch "$TEST_STATE.root-transitional"; echo 2000; exit 0; fi ;;
  shared_deadline) sleep 5 ;;
 esac
fi
if [[ "$step" == unroot && "$TEST_RESTORE_MODE" == nonzero_verified ]]; then
 printf '%s\\n' "$mode" > "$TEST_STATE"; exit 9
fi
if [[ "$step" == shell_identity ]]; then
 case "$TEST_RESTORE_MODE" in
  unknown) echo unknown; exit 0 ;;
  read_failure) exit 9 ;;
  root_once) if [[ ! -f "$TEST_STATE.transitional" ]]; then touch "$TEST_STATE.transitional"; echo 0; exit 0; fi ;;
 esac
fi
if [[ "$step" == "$TEST_FAIL_AT" ]]; then
 case "$step" in root_identity) echo 2000; exit 0 ;; shell_identity) echo 0; exit 0 ;; auto_read) echo 1; exit 0 ;; *) exit 9 ;; esac
fi
printf '%s\\n' "$mode" > "$TEST_STATE"
case "$step" in root_identity) echo 0 ;; shell_identity) echo 2000 ;; auto_read) echo 0 ;; esac
`;
// Control Bash's integer clock at the shared-budget calculation, not with a
// wall-clock sleep that can land on either side of its whole-second boundary.
// The extracted function and the real timeout command remain unchanged.
const sharedDeadlineClock = `
set -T
trap 'if [[ "$BASH_COMMAND" == '"'"'remaining=$((root_deadline - SECONDS))'"'"' ]]; then
  SECONDS=$TEST_CLOCK_NOW
  printf "remaining=%s\\n" "$TEST_ROOT_REMAINING" >> "$test_bin/deadline"
fi' DEBUG
timeout() {
  local status=0
  command timeout "$@" || status=$?
  printf '%s exit=%s\\n' "$*" "$status" >> "$test_bin/timeouts"
  if [[ "$*" == '--kill-after=1s 30s adb -s emulator-5554 wait-for-device' ]]; then
    # Advance reconnect time against the deadline that existed during the wait.
    # Keep that clock value fixed even if a new deadline is wrongly introduced.
    TEST_CLOCK_NOW=$((root_deadline - TEST_ROOT_REMAINING))
    SECONDS=$TEST_CLOCK_NOW
  fi
  return "$status"
}
`;
const clock = (failAt = '', badTime = false, restoreMode = '', rootMode = '', rootRemaining = 0) => temporary(directory => {
  fs.writeFileSync(path.join(directory, 'adb'), fakeAdb, { mode: 0o700 });
  fs.writeFileSync(path.join(directory, 'date'), '#!/usr/bin/env bash\nif [[ "$TEST_BAD_TIME" == 1 ]]; then printf \'1792879320.123456789;false\\n\'; else exec /usr/bin/date "$@"; fi\n', { mode: 0o700 });
  const script = setup + 'export TEST_LOG="$test_bin/order" TEST_STATE="$test_bin/state"\n' +
    (rootMode === 'shared_deadline' ? sharedDeadlineClock : '') + alignment + '\nalign_capture_clock\nprintf "DRIVER_ALLOWED\\n"\n';
  const result = spawnSync(bash, ['-c', script], { cwd: directory, encoding: 'utf8', timeout: 45000, windowsHide: true,
      env: { ...process.env, TEST_DIRECTORY: directory, TEST_NODE_DIRECTORY: path.dirname(process.execPath), TEST_FAIL_AT: failAt, TEST_BAD_TIME: badTime ? '1' : '0', TEST_RESTORE_MODE: restoreMode, TEST_ROOT_MODE: rootMode, TEST_ROOT_REMAINING: String(rootRemaining) } });
  assert.equal(result.error, undefined);
  const lines = name => fs.existsSync(path.join(directory, name)) ? fs.readFileSync(path.join(directory, name), 'utf8').trim().split('\n') : [];
  return { ...result, order: lines('order'), deadline: lines('deadline'), timeouts: lines('timeouts') };
});
test('actual capture clock function validates the setter and restores ordinary shell before driver admission', () => {
  const result = clock(); assert.equal(result.status, 0, result.stderr); assert.deepEqual(result.order, order); assert.match(result.stdout, /DRIVER_ALLOWED/);
});
for (const step of order.filter(value => !['root', 'unroot'].includes(value))) test(`capture clock refuses ${step} failure/readback before the driver`, () => {
  const result = clock(step); assert.equal(result.status, ['root_identity', 'shell_identity', 'auto_read'].includes(step) ? 1 : 9, result.stderr);
  if (['root_identity', 'shell_identity'].includes(step)) {
    const position = order.indexOf(step);
    assert.deepEqual(result.order.slice(0, position), order.slice(0, position));
    assert.ok(result.order.length > position + 1 && result.order.slice(position).every(value => value === step));
  } else assert.deepEqual(result.order, order.slice(0, order.indexOf(step) + 1));
  assert.doesNotMatch(result.stdout, /DRIVER_ALLOWED/);
});

test('nonzero root transport response proceeds only after actual root UID verification', () => {
  const result = clock('', false, '', 'nonzero_verified');
  assert.equal(result.status, 0, result.stderr); assert.deepEqual(result.order, order);
  assert.match(result.stdout, /Capture ADB root transition exit: 9/); assert.match(result.stdout, /DRIVER_ALLOWED/);
});

test('a transitional ordinary UID is polled before the setter and driver admission', () => {
  const result = clock('', false, '', 'shell_once');
  assert.equal(result.status, 0, result.stderr);
  assert.deepEqual(result.order, [...order.slice(0, 3), 'root_identity', ...order.slice(3)]);
  assert.match(result.stdout, /DRIVER_ALLOWED/);
});

for (const mode of ['unknown', 'read_failure', 'nonzero_unverified']) test(`capture clock refuses ${mode} root identity before the setter or driver`, () => {
  const result = clock('', false, '', mode);
  assert.equal(result.status, mode === 'read_failure' ? 9 : 1, result.stderr);
  assert.deepEqual(result.order.slice(0, 2), order.slice(0, 2));
  assert.ok(result.order.slice(2).every(value => value === 'root_identity'));
  if (mode === 'nonzero_unverified') assert.match(result.stdout, /Capture ADB root transition exit: 9/);
  assert.doesNotMatch(result.stdout, /DRIVER_ALLOWED/); assert.ok(!result.order.includes('setter'));
});

test('root reconnect exhausting the shared deadline refuses even the first identity read', () => {
  const result = clock('', false, '', 'shared_deadline', 0);
  assert.equal(result.status, 1, result.stderr);
  assert.deepEqual(result.deadline, ['remaining=0']);
  assert.deepEqual(result.order, order.slice(0, 2));
  assert.deepEqual(result.timeouts, [
    '--kill-after=1s 10s adb -s emulator-5554 root exit=0',
    '--kill-after=1s 30s adb -s emulator-5554 wait-for-device exit=0',
  ]);
  assert.doesNotMatch(result.stdout, /DRIVER_ALLOWED/); assert.ok(!result.order.includes('setter'));
});
test('root reconnect and identity read share one deadline without granting a fresh read budget', () => {
  const result = clock('', false, '', 'shared_deadline', 1);
  assert.equal(result.status, 124, result.stderr);
  assert.deepEqual(result.deadline, ['remaining=1']);
  assert.deepEqual(result.order, order.slice(0, 3));
  // The actual five-second fake ADB read is killed by real timeout with only
  // the remaining second, not a fresh ten-second identity-read allowance.
  assert.deepEqual(result.timeouts, [
    '--kill-after=1s 10s adb -s emulator-5554 root exit=0',
    '--kill-after=1s 30s adb -s emulator-5554 wait-for-device exit=0',
    '--kill-after=1s 1s adb -s emulator-5554 shell id -u exit=124',
  ]);
  assert.doesNotMatch(result.stdout, /DRIVER_ALLOWED/); assert.ok(!result.order.includes('setter'));
});
test('nonzero unroot transport response admits the driver only after actual ordinary UID verification', () => {
  const result = clock('', false, 'nonzero_verified');
  assert.equal(result.status, 0, result.stderr); assert.deepEqual(result.order, order);
  assert.match(result.stdout, /Capture ADB unroot transition exit: 9/); assert.match(result.stdout, /DRIVER_ALLOWED/);
});
test('a transient root identity is polled within the shared bound before actual ordinary UID admission', () => {
  const result = clock('', false, 'root_once');
  assert.equal(result.status, 0, result.stderr); assert.deepEqual(result.order, [...order, 'shell_identity']);
  assert.match(result.stdout, /DRIVER_ALLOWED/);
});
for (const mode of ['unknown', 'read_failure']) test(`capture clock refuses ${mode} restored identity before the driver`, () => {
  const result = clock('', false, mode); assert.equal(result.status, mode === 'unknown' ? 1 : 9, result.stderr);
  assert.deepEqual(result.order, order); assert.doesNotMatch(result.stdout, /DRIVER_ALLOWED/);
});
test('capture clock rejects noncanonical host time before its actual setter', () => {
  const result = clock('', true); assert.equal(result.status, 1); assert.deepEqual(result.order, order.slice(0, 5)); assert.doesNotMatch(result.stdout, /DRIVER_ALLOWED/);
});
