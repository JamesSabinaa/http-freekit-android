import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { spawnSync } from 'node:child_process';

const workflow = fs.readFileSync(new URL('../../.github/workflows/preview-runtime.yml', import.meta.url), 'utf8').replace(/\r\n/g, '\n');
const blocks = [...workflow.matchAll(/^ {10}python3 - <<'PY'\n([\s\S]*?)^ {10}PY$/gm)];
const gates = blocks.filter((match) => match[1].includes('reports = list(Path("app/build/outputs/androidTest-results/connected")'));
assert.equal(gates.length, 1, 'Execute the unique actual workflow Python report gate');
const gate = gates[0][1].replace(/^ {10}/gm, '');
const python = process.platform === 'win32' ? 'python' : 'python3';

// Independent fixed manifest: old ten, exact d4bcc1c B6-U eight, and separate-owner probe three.
// These synthetic XMLs exercise admission only; they are never Android runtime evidence.
const groups = [
  ['com.httpfreekit.android.preview.PreviewActivityTest', [
    'noCaptureWarningAppearsOnEveryPreviewPage',
    'sampleComputerAndAppSelectionsSurviveRotation',
    'simulatedConsentReachesReadyAndStopWithoutClaimingCapture',
    'deniedNotificationAndCancelledVpnConsentStayInPreview',
  ]],
  ['com.httpfreekit.android.preview.InstalledAppsActivityTest', [
    'headlessFixtureSupportsSearchDevelopmentFilterAndToggle',
    'installedSelectionSurvivesRefreshAndRotationWithoutCapture',
    'successfulRefreshPrunesDisabledFixtureAndDoesNotReselectIt',
    'sampleAndInstalledSelectionsRemainSeparate',
  ]],
  ['com.httpfreekit.android.preview.CertificateHelpActivityTest', [
    'realSecuritySettingsReturnAndRotationKeepTrustUnverified',
    'unavailableSettingsAndCopiedDebugExamplesNeverChangeReadiness',
  ]],
  ['com.httpfreekit.android.preview.SelectedCapturePreflightActivityTest', [
    'explicitActionChecksOffMainAndNeverUpgradesPreviewReadiness',
    'unavailablePackageRejectsWithoutChangingSelectionOrPreview',
    'selectionCancellationAndIgnoredInterruptRemainSingleFlight',
    'actualActivityBackgroundAndReturnInvalidateWithoutAutomaticCheck',
    'configurationRecreationRetainsSelectionButSuppressesOldCompletion',
    'refreshAndModeChangesInvalidateWithoutAutomaticChecks',
    'previewLockAndStopSuppressPendingCheckWithoutRequestingPermissions',
    'clearingActualOwnerCancelsAndPermanentlySuppressesLatePublication',
  ]],
  ['com.httpfreekit.android.apps.PackageManagerSelectedPackageProbeTest', [
    'currentCompanionIsAvailable', 'missingPackageIsNotInstalled', 'headlessFixtureIsAvailable',
  ]],
];
const manifest = groups.flatMap(([classname, names]) => names.map((name) => ({ classname, name })));
assert.equal(manifest.length, 21);
assert.equal(new Set(manifest.map(({ classname, name }) => `${classname}#${name}`)).size, 21);

function counters(cases) {
  return { tests: cases.length, failures: cases.filter((c) => c.result === 'failure').length,
    errors: cases.filter((c) => c.result === 'error').length, skipped: cases.filter((c) => c.result === 'skipped').length };
}
function attributes(values) {
  return Object.entries(values).map(([key, value]) => `${key}="${value}"`).join(' ');
}
function render(cases, { wrapped = true, suiteCounters = {}, aggregateCounters = {}, hideResultCounters = false } = {}) {
  const suites = [...new Set(cases.map((c) => c.classname))].map((classname) => {
    const rows = cases.filter((c) => c.classname === classname);
    const counts = hideResultCounters ? { ...counters(rows), failures: 0, errors: 0, skipped: 0 } : counters(rows);
    return `<testsuite name="${classname}" ${attributes({ ...counts, ...suiteCounters })}>${rows.map((c) =>
      `<testcase classname="${c.classname}" name="${c.name}">${c.result ? `<${c.result}/>` : ''}</testcase>`).join('')}</testsuite>`;
  });
  return wrapped ? [`<testsuites ${attributes({ ...counters(cases), ...aggregateCounters })}>${suites.join('')}</testsuites>`] : suites;
}
function run(cases, options = {}, api = '26') {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'freekit-preview-preflight-'));
  try {
    const reports = path.join(directory, 'app/build/outputs/androidTest-results/connected/debug');
    fs.mkdirSync(reports, { recursive: true });
    render(cases, options).forEach((xml, index) => fs.writeFileSync(path.join(reports, `TEST-synthetic-${index}.xml`), xml));
    const result = spawnSync(python, ['-I', '-c', gate], { cwd: directory, encoding: 'utf8', timeout: 5000,
      windowsHide: true, env: { ...process.env, API_LEVEL: api } });
    assert.equal(result.error, undefined, 'The actual Python gate must terminate');
    assert.equal(result.signal, null);
    return result;
  } finally {
    fs.rmSync(directory, { recursive: true, force: true });
  }
}
function refuses(cases, options) {
  const result = run(cases, options);
  assert.equal(result.status, 1, result.stdout + result.stderr);
  assert.equal(result.stdout, '', 'Rejected synthetic results must not emit a passing summary');
}

for (const api of ['26', '37']) {
  for (const wrapped of [true, false]) {
    test(`synthetic exact 21 passing methods accepted: API ${api}, wrapped=${wrapped}`, () => {
      const result = run(manifest, { wrapped }, api);
      assert.equal(result.status, 0, result.stderr);
      assert.deepEqual(JSON.parse(result.stdout), { api, tests: 21, failures: 0, errors: 0, skipped: 0 });
    });
  }
}
for (const row of manifest) {
  test(`synthetic dropped method refused: ${row.name}`, () => refuses(manifest.filter((c) => c !== row)));
}
test('synthetic original ten-only reports refused', () => refuses(manifest.slice(0, 10)));
test('synthetic surplus duplicate refused', () => refuses([...manifest, manifest[10]]));
test('synthetic duplicate replacing required method refused despite count 21', () => refuses([...manifest.slice(0, -1), manifest[10]]));
test('synthetic unexpected method replacing required method refused', () => refuses([...manifest.slice(0, -1), { ...manifest.at(-1), name: 'unexpectedMethod' }]));
test('synthetic unexpected class refused', () => refuses([...manifest.slice(0, -1), { ...manifest.at(-1), classname: 'unexpected.Class' }]));
test('synthetic surplus unexpected method refused', () => refuses([...manifest, { classname: 'unexpected.Class', name: 'extraMethod' }]));
for (const result of ['failure', 'error', 'skipped']) {
  const cases = manifest.map((c, i) => i === 10 ? { ...c, result } : c);
  test(`synthetic ${result} refused with truthful counters`, () => refuses(cases));
  test(`synthetic ${result} refused even with zero result counters`, () => refuses(cases, {
    hideResultCounters: true, aggregateCounters: { failures: 0, errors: 0, skipped: 0 },
  }));
}
test('synthetic suite test-counter mismatch refused', () => refuses(manifest, { suiteCounters: { tests: 21 } }));
for (const field of ['tests', 'failures', 'errors', 'skipped']) {
  test(`synthetic aggregate ${field}-counter mismatch refused`, () => refuses(manifest, {
    aggregateCounters: { [field]: field === 'tests' ? 20 : 1 },
  }));
}
