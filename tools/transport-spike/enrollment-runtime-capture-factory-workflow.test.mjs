import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { spawnSync } from 'node:child_process';

const workflow = fs.readFileSync(new URL('../../.github/workflows/enrollment-runtime.yml', import.meta.url), 'utf8').replace(/\r\n/g, '\n');
const cleanup = /# BEGIN A22 OWNED EMULATOR CLEANUP\n([\s\S]*?)          # END A22 OWNED EMULATOR CLEANUP/.exec(workflow)?.[1].replace(/^ {10}/gm, '');
assert(cleanup);
const bash = process.platform === 'win32' ? 'C:/Program Files/Git/bin/bash.exe' : '/bin/bash';
for (const trapped of [true, false]) for (const status of [0, 7, 124]) {
  test(`actual C2 ${trapped ? 'EXIT' : 'explicit'} cleanup preserves ${status} and joins its owned emulator substitute`, () => {
    const root = fs.realpathSync(os.tmpdir()), directory = fs.mkdtempSync(path.join(root, 'freekit-c2-cleanup-'));
    try {
      fs.writeFileSync(path.join(directory, 'adb'), '#!/usr/bin/env bash\nif [[ "$TEST_STATUS" == 0 ]]; then kill "$TEST_EMULATOR_PID"; exit 0; fi\nexit 9\n', { mode: 0o700 });
      const setup = 'set -euo pipefail\nif command -v cygpath >/dev/null 2>&1; then test_bin="$(cygpath -u "$TEST_DIRECTORY")"; node_bin="$(cygpath -u "$TEST_NODE_DIRECTORY")"; else test_bin="$TEST_DIRECTORY"; node_bin="$TEST_NODE_DIRECTORY"; fi\nexport PATH="$test_bin:$node_bin:$PATH"\n';
      const child = '(printf READY > "$test_bin/ready"; exec sleep 30) &\nemulator_pid=$!\nexport TEST_EMULATOR_PID="$emulator_pid"\n' +
        'deadline=$((SECONDS+5)); while [[ ! -f "$test_bin/ready" ]]; do if ((SECONDS>=deadline)); then kill "$emulator_pid"; wait "$emulator_pid" || true; exit 88; fi; sleep 0.01; done\ndriver_status="$TEST_STATUS"\n';
      const end = trapped ? 'trap \'status=$?; if cleanup "$status"; then exit 0; else exit $?; fi\' EXIT\nexit "$TEST_STATUS"\n' : 'if cleanup "$TEST_STATUS"; then exit 0; else exit $?; fi\n';
      const result = spawnSync(bash, ['-c', setup + child + cleanup + end], { cwd: directory, timeout: 15000, encoding: 'utf8', windowsHide: true,
        env: { ...process.env, TEST_DIRECTORY: directory, TEST_NODE_DIRECTORY: path.dirname(process.execPath), TEST_STATUS: String(status), A22_SUITE: 'c2', GITHUB_SHA: 'a'.repeat(40), API_LEVEL: '26' } });
      assert.equal(result.error, undefined); assert.equal(result.status, status, result.stderr);
      const value = JSON.parse(fs.readFileSync(path.join(directory, 'build/reports/capture-factory/host-cleanup.json')));
      assert.equal(value.format, 'http-freekit-c2-host-cleanup'); assert.equal(value.driverExitCode, status); assert.equal(value.stopExitCode, status === 0 ? 0 : 9);
      assert(value.terminationObserved && value.joinObserved); assert.notEqual(value.emulatorExitCode, 127);
    } finally { assert.equal(path.dirname(directory), root); assert(path.basename(directory).startsWith('freekit-c2-cleanup-')); fs.rmSync(directory, { recursive: true, force: true }); }
  });
}
