import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { spawnSync } from 'node:child_process';
import { enrolledTunReportPaths } from './enrolled-tun-descriptor.mjs';
import { C3_DESKTOP_COMMIT } from './gateway-origin-desktop.mjs';

const workflow = fs.readFileSync(new URL('../../.github/workflows/enrollment-runtime.yml', import.meta.url), 'utf8').replace(/\r\n/g, '\n');
const bash = process.platform === 'win32' ? 'C:/Program Files/Git/bin/bash.exe' : '/bin/bash';
function runBlock(name) {
  const lines = workflow.split('\n'), start = lines.indexOf('      - name: ' + name);
  assert(start >= 0);
  const run = lines.findIndex((line, index) => index > start && line === '        run: |');
  assert(run > start);
  const result = [];
  for (const line of lines.slice(run + 1)) {
    if (line.trim() && !line.startsWith('          ')) break;
    result.push(line.slice(10));
  }
  return result.join('\n') + '\n';
}
const guard = runBlock('Require integrated enrollment producers and verifier');
const producers = [
  'tools/transport-spike/enrolled-tun-results.mjs',
  'tools/transport-spike/run-enrolled-tun-runtime.mjs',
  'tools/transport-spike/enrolled-tun-packages.mjs',
  'tools/transport-spike/android/src/androidTest/kotlin/com/httpfreekit/interop/DraftEnrolledTunInteropTest.kt',
  'tools/transport-spike/run-enrollment-runtime.mjs',
  'tools/transport-spike/companion-enrollment-worker.mjs',
  'tools/transport-spike/enrollment-runtime-results.mjs',
  'scripts/verify-enrollment-runtime.mjs',
];
function selected(suite, missing, check) {
  const root = fs.realpathSync(os.tmpdir()), directory = fs.mkdtempSync(path.join(root, 'freekit-c5-workflow-'));
  try {
    for (const name of producers.filter(name => name !== missing)) {
      const filename = path.join(directory, name); fs.mkdirSync(path.dirname(filename), { recursive: true }); fs.writeFileSync(filename, '');
    }
    const output = path.join(directory, 'outputs');
    const setup = 'set -euo pipefail\nif command -v cygpath >/dev/null 2>&1; then export GITHUB_OUTPUT="$(cygpath -u "$GITHUB_OUTPUT")"; fi\n';
    const result = spawnSync(bash, ['-c', setup + guard], { cwd: directory, timeout: 5000, encoding: 'utf8', windowsHide: true,
      env: { ...process.env, A22_SUITE: suite, GITHUB_OUTPUT: output } });
    assert.equal(result.error, undefined);
    check(result, fs.existsSync(output) ? fs.readFileSync(output, 'utf8') : null);
  } finally {
    assert.equal(path.dirname(directory), root); assert(path.basename(directory).startsWith('freekit-c5-workflow-'));
    fs.rmSync(directory, { recursive: true, force: true });
  }
}

test('actual C5 workflow guard selects the four descriptor paths without starting any runtime', () => {
  selected('c5', null, (result, output) => {
    assert.equal(result.status, 0, result.stderr);
    assert.deepEqual(Object.fromEntries(output.trim().split('\n').map(line => line.split('='))), enrolledTunReportPaths);
  });
});
test('actual C5 workflow guard rejects a missing producer before report selection', () => {
  selected('c5', 'tools/transport-spike/run-enrolled-tun-runtime.mjs', (result, output) => {
    assert.notEqual(result.status, 0); assert.equal(output, null);
  });
});
test('actual workflow guard refuses an unknown suite before report selection', () => {
  selected('unknown', null, (result, output) => { assert.notEqual(result.status, 0); assert.equal(output, null); });
});
test('hosted C5 pins the reviewed desktop and installs the native dependency required by its APK', () => {
  assert.equal(/C5_DESKTOP_COMMIT: ([0-9a-f]{40})/.exec(workflow)?.[1], C3_DESKTOP_COMMIT);
  const core = fs.readFileSync(new URL('../../core-capture/build.gradle.kts', import.meta.url), 'utf8');
  const ndk = /ndkVersion = "([0-9.]+)"/.exec(core)?.[1]; assert(ndk);
  assert(runBlock('Accept SDK licences and install emulator packages').includes(`'ndk;${ndk}'`));
  const runtime = runBlock('Run selected enrollment suite on a fresh AVD');
  assert(runtime.includes('driver_args+=(--desktop-root "$C5_DESKTOP_ROOT" --desktop-commit "$C5_DESKTOP_COMMIT")'));
  assert(runtime.includes('verify_args+=(--desktop-source "$C5_DESKTOP_COMMIT")'));
});
