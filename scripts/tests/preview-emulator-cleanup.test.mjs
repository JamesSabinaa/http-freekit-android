import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { spawnSync } from 'node:child_process';

const workflow = fs.readFileSync(new URL('../../.github/workflows/preview-runtime.yml', import.meta.url), 'utf8').replace(/\r\n/g, '\n');
const matched = /          # BEGIN B4 OWNED EMULATOR CLEANUP\n([\s\S]*?)          # END B4 OWNED EMULATOR CLEANUP/.exec(workflow);
assert(matched, 'Execute the actual checked preview cleanup block');
const cleanup = matched[1].replace(/^ {10}/gm, '');
const bash = process.platform === 'win32' ? 'C:/Program Files/Git/bin/bash.exe' : '/bin/bash';
const pythonResult = spawnSync(process.platform === 'win32' ? 'python' : 'python3', ['-c', 'import sys; print(sys.executable)'], { encoding: 'utf8', timeout: 5000, windowsHide: true });
assert.equal(pythonResult.status, 0, 'Actual Python is required by the workflow cleanup');
const python = pythonResult.stdout.trim(), source = 'a'.repeat(40);
const fields = ['format', 'revision', 'sourceCommit', 'api', 'runtimeExitCode', 'fixtureInstallAttempted', 'fixtureEnableExitCode',
  'fixtureUninstallExitCode', 'emulatorStarted', 'stopAttempted', 'stopExitCode', 'termAttempted', 'killAttempted',
  'terminationObserved', 'joinObserved', 'emulatorExitCode', 'cleanupComplete', 'accepted'].sort();

const fakeAdb = `#!/usr/bin/env bash
set -euo pipefail
[[ "$1" == -s && "$2" == emulator-5554 ]] || exit 91
shift 2
if [[ "$1" == shell ]]; then op=enable; elif [[ "$1" == uninstall ]]; then op=uninstall; elif [[ "$1" == emu && "$2" == kill ]]; then op=stop; else exit 92; fi
printf '%s\\n' "$op" >> "$TEST_DIRECTORY/calls"
if [[ "$op" == enable && "$TEST_FIXTURE_FAILURE" == enable ]]; then echo CANARY_PRIVATE >&2; exit 23; fi
if [[ "$op" == uninstall && "$TEST_FIXTURE_FAILURE" == uninstall ]]; then echo CANARY_PRIVATE >&2; exit 24; fi
if [[ "$op" != stop ]]; then exit 0; fi
if [[ "$TEST_STOP_MODE" == failed ]]; then exit 9; fi
if [[ "$TEST_STOP_MODE" == hung ]]; then trap '' TERM; exec sleep 30; fi
kill -TERM "$TEST_EMULATOR_PID"
for ((attempt=0; attempt<300; attempt++)); do
  if ! kill -0 "$TEST_EMULATOR_PID" 2>/dev/null; then exit 0; fi
  sleep 0.01
done
exit 93
`;
const fakePython = `#!/usr/bin/env bash
if [[ "$TEST_REPORT_MODE" == failed ]]; then exit 19; fi
if [[ "$TEST_REPORT_MODE" == hung ]]; then trap '' TERM; exec sleep 30; fi
exec "$TEST_PYTHON" "$@"
`;

function run({ viaTrap = false, originalStatus = 0, stopMode = 'graceful', emulatorMode = 'normal', fixtureFailure = 'none',
  fixtureAttempted = true, reportMode = 'normal', invalidWait = false, abortBeforeCleanup = false } = {}, verify) {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'freekit-preview-cleanup-'));
  let fallbackNeeded = false;
  try {
    fs.writeFileSync(path.join(directory, 'adb'), fakeAdb, { mode: 0o700 });
    fs.writeFileSync(path.join(directory, 'python3'), fakePython, { mode: 0o700 });
    const setup = `set -euo pipefail
test_bin="$TEST_DIRECTORY"
python_exe="$TEST_PYTHON"
if command -v cygpath >/dev/null 2>&1; then test_bin="$(cygpath -u "$test_bin")"; python_exe="$(cygpath -u "$python_exe")"; fi
export TEST_DIRECTORY="$test_bin" TEST_PYTHON="$python_exe" PATH="$test_bin:$PATH"
if [[ "$TEST_EMULATOR_MODE" == ignored ]]; then
  bash -c 'trap "" TERM; printf ready > "$TEST_DIRECTORY/emulator-ready"; exec sleep 30' >/dev/null 2>&1 &
else
  sleep 30 >/dev/null 2>&1 &
fi
emulator_pid=$!
printf '%s\\n' "$emulator_pid" > "$TEST_DIRECTORY/emulator-pid"
export TEST_EMULATOR_PID="$emulator_pid"
fixture_package=com.httpfreekit.fixture.installedapps
fixture_install_attempted="$TEST_FIXTURE_ATTEMPTED"
if [[ "$TEST_EMULATOR_MODE" == ignored ]]; then
  for ((attempt=0; attempt<200; attempt++)); do [[ -f "$TEST_DIRECTORY/emulator-ready" ]] && break; sleep 0.01; done
  [[ -f "$TEST_DIRECTORY/emulator-ready" ]]
fi
${invalidWait ? 'wait() { return 127; }\n' : ''}${abortBeforeCleanup ? 'exit 31\n' : ''}`;
    const end = viaTrap ? 'exit "$TEST_ORIGINAL_STATUS"\n' :
      'if cleanup "$TEST_ORIGINAL_STATUS"; then result=0; else result=$?; fi\nbuiltin wait "$emulator_pid" 2>/dev/null || true\nexit "$result"\n';
    const started = performance.now();
    const result = spawnSync(bash, ['-c', setup + cleanup + end], { cwd: directory, encoding: 'utf8', timeout: 35000, windowsHide: true,
      env: { ...process.env, GITHUB_SHA: source, API_LEVEL: '37', TEST_DIRECTORY: directory, TEST_PYTHON: python,
        TEST_ORIGINAL_STATUS: String(originalStatus), TEST_STOP_MODE: stopMode, TEST_EMULATOR_MODE: emulatorMode,
        TEST_FIXTURE_FAILURE: fixtureFailure, TEST_FIXTURE_ATTEMPTED: String(fixtureAttempted), TEST_REPORT_MODE: reportMode } });
    const elapsed = performance.now() - started;
    assert.equal(result.error, undefined, 'The actual bounded cleanup must terminate');
    assert.doesNotMatch(result.stdout + result.stderr, /CANARY_PRIVATE|invitation|PRIVATE KEY/i);
    const reportPath = path.join(directory, 'build/reports/preview/host-cleanup.json');
    const record = fs.existsSync(reportPath) ? JSON.parse(fs.readFileSync(reportPath, 'utf8')) : null;
    const callsPath = path.join(directory, 'calls');
    const calls = fs.existsSync(callsPath) ? fs.readFileSync(callsPath, 'utf8').trim().split('\n') : [];
    if (record) {
      assert.deepEqual(Object.keys(record).sort(), fields);
      assert.equal(record.format, 'http-freekit-preview-host-cleanup'); assert.equal(record.revision, 1);
      assert.equal(record.sourceCommit, source); assert.equal(record.api, 37); assert.equal(record.runtimeExitCode, originalStatus);
      assert(record.emulatorStarted && record.stopAttempted && record.terminationObserved);
      assert.equal(record.fixtureInstallAttempted, fixtureAttempted);
      assert.deepEqual(calls, fixtureAttempted ? ['enable', 'uninstall', 'stop'] : ['stop']);
      assert.equal(record.fixtureEnableExitCode, fixtureAttempted ? fixtureFailure === 'enable' ? 23 : 0 : null);
      assert.equal(record.fixtureUninstallExitCode, fixtureAttempted ? fixtureFailure === 'uninstall' ? 24 : 0 : null);
    }
    verify({ result, record, elapsed });
  } finally {
    assert.equal(path.dirname(path.resolve(directory)), path.resolve(os.tmpdir()));
    assert.match(path.basename(directory), /^freekit-preview-cleanup-/);
    // spawnSync joined the Bash owner. Independently stop any retained substitute
    // left by an early owner failure; do not claim a grandchild wait here.
    const fallback = spawnSync(bash, ['-c', `set -euo pipefail
test_bin="$TEST_DIRECTORY"
if command -v cygpath >/dev/null 2>&1; then test_bin="$(cygpath -u "$test_bin")"; fi
[[ -f "$test_bin/emulator-pid" ]] || exit 0
read -r retained_pid < "$test_bin/emulator-pid"
[[ "$retained_pid" =~ ^[1-9][0-9]{0,9}$ ]] || exit 91
if ! kill -0 "$retained_pid" 2>/dev/null; then exit 0; fi
printf 'fallback-needed\\n'
kill -TERM "$retained_pid" 2>/dev/null || true
for ((attempt=0; attempt<50; attempt++)); do
  if ! kill -0 "$retained_pid" 2>/dev/null; then exit 0; fi
  timeout --kill-after=1s 1s sleep 0.1
done
kill -KILL "$retained_pid" 2>/dev/null || true
for ((attempt=0; attempt<50; attempt++)); do
  if ! kill -0 "$retained_pid" 2>/dev/null; then exit 0; fi
  timeout --kill-after=1s 1s sleep 0.1
done
exit 92
`], { encoding: 'utf8', timeout: 30000, windowsHide: true, env: { ...process.env, TEST_DIRECTORY: directory } });
    assert.equal(fallback.error, undefined, 'Independent test-child teardown must terminate');
    assert.equal(fallback.status, 0, 'Retained test substitute must be absent before its directory is removed');
    fallbackNeeded = fallback.stdout.includes('fallback-needed');
    fs.rmSync(directory, { recursive: true, force: true });
  }
  return { fallbackNeeded };
}

for (const viaTrap of [false, true]) for (const originalStatus of [0, 7, 124]) {
  test(`actual preview ${viaTrap ? 'EXIT-trap' : 'explicit'} cleanup preserves ${originalStatus} and joins its owned child`, () => {
    run({ viaTrap, originalStatus }, ({ result, record }) => {
      assert.equal(result.status, originalStatus); assert.equal(record.stopExitCode, 0);
      assert(record.joinObserved && record.cleanupComplete); assert.equal(record.emulatorExitCode, 143);
      assert.equal(record.accepted, originalStatus === 0); assert.equal(record.killAttempted, false);
    });
  });
}

test('failed ADB stop is recorded while real fallback TERM and wait still attest complete cleanup', () => {
  run({ stopMode: 'failed' }, ({ result, record }) => {
    assert.equal(result.status, 0); assert.equal(record.stopExitCode, 9); assert(record.termAttempted && !record.killAttempted);
    assert(record.terminationObserved && record.joinObserved && record.cleanupComplete && record.accepted); assert.equal(record.emulatorExitCode, 143);
  });
});
test('an actual TERM-ignoring hung stop command is killed within its bound before owned-emulator fallback', () => {
  run({ stopMode: 'hung' }, ({ result, record, elapsed }) => {
    assert.equal(result.status, 0); assert([124, 137].includes(record.stopExitCode)); assert(elapsed >= 10000 && elapsed < 20000);
    assert(record.termAttempted && record.joinObserved && record.accepted); assert.equal(record.emulatorExitCode, 143);
  });
});
test('a real TERM-ignoring emulator child reaches retained-PID KILL, observed exit and actual wait', () => {
  run({ stopMode: 'failed', emulatorMode: 'ignored' }, ({ result, record }) => {
    assert.equal(result.status, 0); assert(record.termAttempted && record.killAttempted);
    assert(record.terminationObserved && record.joinObserved && record.accepted); assert.equal(record.emulatorExitCode, 137);
  });
});
for (const fixtureFailure of ['enable', 'uninstall']) test(`fixture ${fixtureFailure} failure retains both command outcomes and cannot pass cleanup`, () => {
  run({ fixtureFailure }, ({ result, record }) => {
    assert.equal(result.status, 1); assert(record.terminationObserved && record.joinObserved);
    assert.equal(record.cleanupComplete, false); assert.equal(record.accepted, false);
  });
});
test('a reported wait failure cannot become a joined or accepted emulator', () => {
  run({ invalidWait: true }, ({ result, record }) => {
    assert.equal(result.status, 1); assert.equal(record.joinObserved, false); assert.equal(record.emulatorExitCode, 127);
    assert.equal(record.cleanupComplete, false); assert.equal(record.accepted, false);
  });
});
test('an early exit without fixture installation remains unaccepted even when owned cleanup joins', () => {
  run({ fixtureAttempted: false }, ({ result, record }) => {
    assert.equal(result.status, 1); assert(record.cleanupComplete && record.joinObserved); assert.equal(record.accepted, false);
  });
});
for (const reportMode of ['failed', 'hung']) test(`a ${reportMode} report writer cannot turn original success into accepted cleanup`, () => {
  run({ reportMode }, ({ result, record }) => { assert.equal(result.status, 1); assert.equal(record, null); });
});

test('independent harness teardown removes a retained substitute after an early Bash-owner failure', () => {
  const result = run({ abortBeforeCleanup: true }, ({ result, record }) => {
    assert.equal(result.status, 31); assert.equal(record, null);
  });
  assert.equal(result.fallbackNeeded, true);
});
