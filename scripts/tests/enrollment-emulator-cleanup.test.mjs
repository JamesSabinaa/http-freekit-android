import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { spawnSync } from 'node:child_process';
import { decodeEnrollmentHostCleanup, verifyEnrollmentHostCleanup } from '../../tools/transport-spike/enrollment-runtime-results.mjs';
import { source } from '../../tools/transport-spike/enrollment-runtime-test-fixtures.mjs';

const workflow = fs.readFileSync(new URL('../../.github/workflows/enrollment-runtime.yml', import.meta.url), 'utf8').replace(/\r\n/g, '\n');
const block = /          # BEGIN A22 OWNED EMULATOR CLEANUP\r?\n([\s\S]*?)          # END A22 OWNED EMULATOR CLEANUP/.exec(workflow);
assert.ok(block, 'The checked workflow cleanup must be tested directly');
const cleanup = block[1].replace(/^ {10}/gm, '');
const bash = process.platform === 'win32' ? 'C:/Program Files/Git/bin/bash.exe' : '/bin/bash';
const nodeDirectory = path.dirname(process.execPath);

for (const viaTrap of [false, true]) for (const originalStatus of [0, 7, 124]) {
  test(`actual workflow cleanup ${viaTrap ? 'EXIT trap' : 'explicit'} preserves status ${originalStatus} and joins an owned child`, () => {
    const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'freekit-a22-cleanup-'));
    try {
      fs.writeFileSync(path.join(directory, 'adb'), '#!/usr/bin/env bash\nif [[ "$TEST_STOP_MODE" == graceful ]]; then kill "$TEST_EMULATOR_PID"; exit 0; fi\nexit 9\n', { mode: 0o700 });
      const setup = 'set -euo pipefail\n' +
        'if command -v cygpath >/dev/null 2>&1; then test_bin="$(cygpath -u "$TEST_DIRECTORY")"; node_bin="$(cygpath -u "$TEST_NODE_DIRECTORY")"; else test_bin="$TEST_DIRECTORY"; node_bin="$TEST_NODE_DIRECTORY"; fi\n' +
        'export PATH="$test_bin:$node_bin:$PATH"\n' +
        'sleep 30 &\nemulator_pid=$!\nexport TEST_EMULATOR_PID="$emulator_pid"\ndriver_status="$TEST_ORIGINAL_STATUS"\n';
      const end = viaTrap
        ? 'trap \'status=$?; if cleanup "$status"; then exit 0; else exit $?; fi\' EXIT\nexit "$TEST_ORIGINAL_STATUS"\n'
        : 'if cleanup "$TEST_ORIGINAL_STATUS"; then exit 0; else exit $?; fi\n';
      const result = spawnSync(bash, ['-c', setup + cleanup + end], {
        cwd: directory, encoding: 'utf8', timeout: 15000, windowsHide: true,
        env: { ...process.env, GITHUB_SHA: source, API_LEVEL: '26', TEST_DIRECTORY: directory,
          TEST_NODE_DIRECTORY: nodeDirectory, TEST_ORIGINAL_STATUS: String(originalStatus), TEST_STOP_MODE: originalStatus === 0 ? 'graceful' : 'failed' },
      });
      assert.equal(result.error, undefined); assert.equal(result.status, originalStatus, result.stderr);
      const reportPath = path.join(directory, 'build/reports/enrollment-runtime/host-cleanup.json');
      const report = decodeEnrollmentHostCleanup(fs.readFileSync(reportPath));
      assert.equal(report.driverExitCode, originalStatus); assert.equal(report.stopExitCode, originalStatus === 0 ? 0 : 9);
      assert.equal(report.terminationObserved, true); assert.equal(report.joinObserved, true); assert.notEqual(report.emulatorExitCode, null);
      if (originalStatus === 0) assert.equal(verifyEnrollmentHostCleanup(report, { source, api: 26 }).emulatorJoined, true);
      else assert.throws(() => verifyEnrollmentHostCleanup(report, { source, api: 26 }), /host_cleanup_failed/);
      assert.doesNotMatch(result.stdout + result.stderr, /PRIVATE|input-v1|invitation/i);
    } finally {
      assert.equal(path.dirname(path.resolve(directory)), path.resolve(os.tmpdir()));
      assert.match(path.basename(directory), /^freekit-a22-cleanup-/);
      fs.rmSync(directory, { recursive: true, force: true });
    }
  });
}
