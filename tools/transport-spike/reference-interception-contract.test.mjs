import test from 'node:test';
import assert from 'node:assert/strict';
import { inspect } from 'node:util';
import { createHash } from 'node:crypto';
import fs from 'node:fs';
import { referenceInterceptionProfile as profile, referenceInterceptionResponse, ReferenceInterceptionError } from './reference-interception-contract.mjs';

test('reference interception profile is fixed and does not add a wire mode', () => {
  assert.ok(Object.isFrozen(profile));
  assert.deepEqual(profile, { address: '198.18.0.2', hostname: 'reference-target.invalid', path: '/reference/proof',
    httpPort: 80, httpsPort: 443, maxBodyBytes: 4096, maxHeaderBytes: 4096, maxOwners: 2, timeoutMillis: 5000 });
  assert.throws(() => { profile.address = '127.0.0.1'; }, TypeError);
});

test('actual origin response binds bounded bytes and returns independent buffers', () => {
  const body = Buffer.from('synthetic private body');
  const expected = Buffer.from('reference-origin:' + createHash('sha256').update(body).digest('hex'));
  const first = referenceInterceptionResponse(body);
  assert.deepEqual(first, expected);
  first.fill(0);
  assert.deepEqual(referenceInterceptionResponse(body), expected);
  assert.notDeepEqual(referenceInterceptionResponse(Buffer.from('different')), expected);
  assert.equal(referenceInterceptionResponse(Buffer.alloc(4096)).length, 81);
  for (const bad of [null, 'body', {}, Buffer.alloc(4097)]) assert.throws(() => referenceInterceptionResponse(bad), ReferenceInterceptionError);
});

test('host workflow requires all five reference suites without a desktop fallback or suppressed failure', () => {
  const workflow = fs.readFileSync(new URL('../../.github/workflows/android.yml', import.meta.url), 'utf8');
  const block = /      - name: Test fixed reference HTTP and HTTPS interception composition\n([\s\S]*?)(?=      - name:)/.exec(workflow)?.[1];
  assert.ok(block);
  const command = block.replace(/\s+/g, ' ').trim();
  assert.equal(command, 'run: >- node --test tools/transport-spike/reference-interception-contract.test.mjs ' +
    'tools/transport-spike/reference-interception-assets.test.mjs tools/transport-spike/reference-interception-backend.test.mjs ' +
    'tools/transport-spike/reference-interception-enrollment.test.mjs tools/transport-spike/reference-interception-peer.test.mjs');
  assert.doesNotMatch(block, /continue-on-error|desktop|\|\||--test-skip|--test-name-pattern/);
});

test('reference JVM task is isolated, fresh and strict without changing desktop prerequisites', () => {
  const build = fs.readFileSync(new URL('../capture-spike/transport/build.gradle.kts', import.meta.url), 'utf8');
  const task = /tasks\.register<Test>\("testReferenceIntegration"\) \{([\s\S]*)\}\s*$/.exec(build)?.[1];
  assert.ok(task);
  for (const line of [
    'dependsOn(unit.testClassesDirs, unit.classpath)',
    'testClassesDirs = unit.testClassesDirs', 'classpath = unit.classpath',
    'javaLauncher.set(unit.javaLauncher)', 'workingDir = rootProject.projectDir', 'useJUnit()',
    'outputs.upToDateWhen { false }',
    'outputs.doNotCacheIf("Requires fresh reference gateway and actual TLS execution") { true }',
    'systemProperty("com.sun.net.ssl.requireCloseNotify", "true")',
    'includeTestsMatching("com.httpfreekit.capture.transport.EnrolledCaptureReferenceTest")',
    'isFailOnNoMatchingTests = true',
  ]) assert.ok(task.includes(line));
  assert.doesNotMatch(task, /verifyDesktop|FREEKIT_DESKTOP|ignoreFailures|onlyIf/);
  for (const [name, testClass] of [['testDesktopIntegration', 'EnrolledCaptureDesktopTest'],
    ['testDesktopHttpsIntegration', 'EnrolledCaptureHttpsDesktopTest'],
    ['testDesktopPolicyIntegration', 'EnrolledCapturePolicyDesktopTest'],
    ['testReferenceIntegration', 'EnrolledCaptureReferenceTest']]) {
    assert.ok(build.includes(`if (name != "${name}") exclude("**/${testClass}*.class")`));
  }
  const workflow = fs.readFileSync(new URL('../../.github/workflows/android.yml', import.meta.url), 'utf8');
  assert.ok(workflow.includes(':capture-transport-research:testReferenceIntegration'));
  assert.ok(workflow.includes('tools/capture-spike/transport/build/test-results/testReferenceIntegration/'));
});

test('finite errors never serialize supplied provider or path details or invent a join', () => {
  const error = new ReferenceInterceptionError('/private/provider/SECRET', 'true');
  assert.deepEqual(error.toJSON(), { code: 'backend_failed', joined: false });
  for (const text of [String(error), JSON.stringify(error), inspect(error)]) assert.doesNotMatch(text, /SECRET|private|provider/);
  assert.deepEqual(new ReferenceInterceptionError('cleanup_unjoined', false).toJSON(), { code: 'cleanup_unjoined', joined: false });
});
