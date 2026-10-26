import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import { referenceTunReportPaths } from './reference-tun-descriptor.mjs';

const workflow = fs.readFileSync(new URL('../../.github/workflows/reference-tun-runtime.yml', import.meta.url), 'utf8');
const enrollment = fs.readFileSync(new URL('../../.github/workflows/enrollment-runtime.yml', import.meta.url), 'utf8');

test('reference runtime is a distinct manual pinned two-API workflow without desktop or alias admission', () => {
  assert.match(workflow, /on:\n  workflow_dispatch:\n\npermissions:/);
  assert.match(workflow, /contents: read/);
  assert.match(workflow, /cancel-in-progress: false/);
  for (const value of ["api: '26'", "api: '37'", 'system-images;android-26;default;x86_64',
    'system-images;android-37.0;default;x86_64', "java-version: '17'", "node-version: '24.22.1'"])
    assert.ok(workflow.includes(value));
  assert.doesNotMatch(workflow, /desktop-root|desktop-commit|C5_DESKTOP|C2_DESKTOP|A22_SUITE|sysctl|ip addr|continue-on-error/);
  assert.match(workflow, /run-reference-tun-runtime\.mjs --serial emulator-5554/);
  assert.match(workflow, /python3 -I scripts\/verify-reference-tun-runtime\.py --source "\$GITHUB_SHA" --api "\$API_LEVEL" --started "\$started"/);
});

test('reference runtime preserves the actual checked bounded clock and owned process cleanup', () => {
  const clock = /          # BEGIN A22 FRESH AVD CLOCK ALIGNMENT\n[\s\S]*?          # END A22 FRESH AVD CLOCK ALIGNMENT/;
  assert.equal(clock.exec(workflow)?.[0], clock.exec(enrollment)?.[0]);
  const beforeRecord = /          cleanup\(\) \{[\s\S]*?            if ! node --input-type=module <<'JS'/;
  assert.equal(beforeRecord.exec(workflow)?.[0], beforeRecord.exec(enrollment)?.[0]);
  const afterRecord = /            then cleanup_status=1; fi[\s\S]*?          # END A22 OWNED EMULATOR CLEANUP/;
  assert.equal(afterRecord.exec(workflow)?.[0], afterRecord.exec(enrollment)?.[0]);
  assert.match(workflow, /format: 'http-freekit-reference-tun-host-cleanup', revision: 1/);
  assert.match(workflow, /const root = 'reference-tun';/);
  for (const field of ['sourceCommit', 'api', 'driverExitCode', 'emulatorStarted', 'stopAttempted',
    'stopExitCode', 'terminationObserved', 'joinObserved', 'emulatorExitCode']) assert.ok(workflow.includes(field + ':'));
  assert.match(workflow, /if cleanup "\$driver_status"; then\n            python3 -I/);
});

test('host validation requires all seven new suites and the independent Python verifier tests', () => {
  const host = fs.readFileSync(new URL('../../.github/workflows/android.yml', import.meta.url), 'utf8');
  const block = /      - name: Test separate Android reference TUN fixture and runtime owners\n([\s\S]*?)(?=      - name:)/.exec(host)?.[1];
  assert.ok(block);
  assert.equal(block.replace(/\s+/g, ' ').trim(), 'run: >- node --test ' + [
    'reference-tun-fixture.test.mjs', 'reference-tun-worker.test.mjs', 'reference-tun-worker-client.test.mjs',
    'reference-tun-descriptor.test.mjs', 'reference-tun-results.test.mjs', 'reference-tun-driver.test.mjs',
    'reference-tun-workflow.test.mjs',
  ].map(name => 'tools/transport-spike/' + name).join(' '));
  assert.doesNotMatch(block, /continue-on-error|\|\||--test-skip|--test-name-pattern/);
  assert.ok(host.includes("python3 -I -m unittest discover -s scripts/tests -p 'test_reference_tun_runtime.py'"));
});

test('reference runtime publishes only its four exact sanitized evidence paths', () => {
  const retained = workflow.split('          path: |\n')[1]?.trim().split('\n').map(line => line.trim());
  assert.deepEqual(retained, Object.values(referenceTunReportPaths));
  assert.match(workflow, /name: reference-tun-api-\$\{\{ matrix\.api \}\}-results/);
  assert.match(workflow, /if: always\(\)/);
  for (const value of ['reference-tun-descriptor.mjs', 'reference-tun-results.mjs', 'reference-tun-worker-client.mjs',
    'run-reference-tun-runtime.mjs', 'verify-reference-tun-runtime.py', 'DraftReferenceTunInteropTest.kt'])
    assert.ok(workflow.includes('test -f ') && workflow.includes(value));
});
