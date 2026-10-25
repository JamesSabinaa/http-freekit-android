import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { spawnSync } from 'node:child_process';

const workflow = fs.readFileSync(new URL('../../.github/workflows/capture-cold-runtime.yml', import.meta.url), 'utf8').replace(/\r\n/g, '\n');
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
  test(`actual cold TCP workflow ${viaTrap ? 'EXIT' : 'explicit'} cleanup preserves ${status} and joins the owned emulator substitute`, () => temporary(directory => {
    fs.writeFileSync(path.join(directory, 'adb'), '#!/usr/bin/env bash\nif [[ "$TEST_STATUS" == 0 ]]; then kill "$TEST_EMULATOR_PID"; exit 0; fi\nexit 9\n', { mode: 0o700 });
    const child = '(printf READY > "$test_bin/ready"; exec sleep 30) &\nemulator_pid=$!\nexport TEST_EMULATOR_PID="$emulator_pid"\n' +
      'deadline=$((SECONDS+5)); while [[ ! -f "$test_bin/ready" ]]; do if ((SECONDS>=deadline)); then kill "$emulator_pid"; wait "$emulator_pid" || true; exit 88; fi; sleep 0.01; done\ndriver_status="$TEST_STATUS"\n';
    const end = viaTrap ? 'trap \'status=$?; if cleanup "$status"; then exit 0; else exit $?; fi\' EXIT\nexit "$TEST_STATUS"\n' : 'if cleanup "$TEST_STATUS"; then exit 0; else exit $?; fi\n';
    const result = spawnSync(bash, ['-c', setup + child + cleanup + end], { cwd: directory, encoding: 'utf8', timeout: 15000, windowsHide: true,
      env: { ...process.env, TEST_DIRECTORY: directory, TEST_NODE_DIRECTORY: path.dirname(process.execPath), TEST_STATUS: String(status), GITHUB_SHA: 'a'.repeat(40), API_LEVEL: '26' } });
    assert.equal(result.error, undefined); assert.equal(result.status, status, result.stderr);
    const report = JSON.parse(fs.readFileSync(path.join(directory, 'build/reports/capture-cold-tcp/host-cleanup.json'), 'utf8'));
    assert.equal(report.driverExitCode, status); assert.equal(report.stopExitCode, status === 0 ? 0 : 9);
    assert.equal(report.terminationObserved, true); assert.equal(report.joinObserved, true); assert.notEqual(report.emulatorExitCode, 127);
    assert.equal(report.format, 'http-freekit-capture-cold-host-cleanup');
  }));
}

test('cold workflow keeps the checked root, clock and restored-shell block byte-identical', () => {
  const original = fs.readFileSync(new URL('../../.github/workflows/capture-runtime.yml', import.meta.url), 'utf8').replace(/\r\n/g, '\n');
  const clock = /          # BEGIN C1 FRESH AVD CLOCK ALIGNMENT\n([\s\S]*?)          # END C1 FRESH AVD CLOCK ALIGNMENT/.exec(original);
  assert.ok(clock); assert.equal(alignment, clock[1].replace(/^ {10}/gm, ''));
});
