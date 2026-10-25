import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { createEnrollmentHost, enrollmentPassed as passed, enrollmentShellQuote as quote } from '../transport-spike/enrollment-runtime-host.mjs';
import { createCaptureFixture } from './capture-fixture.mjs';
import { captureColdClass, captureColdMethod, captureColdProblem, captureColdReportAccepted, captureColdXml, parseCaptureColdInvocation } from './capture-cold-results.mjs';

const root = fileURLToPath(new URL('../../', import.meta.url));
const packages = [
  ['tools/capture-spike/runtime/build/outputs/apk/debug', 'com.httpfreekit.capturetest'],
  ['tools/capture-spike/runtime/build/outputs/apk/androidTest/debug', 'com.httpfreekit.capturetest.test'],
  ['tools/capture-spike/traffic/build/outputs/apk/debug', 'com.httpfreekit.capturetraffic'],
];
export function captureColdOptions(args, env = process.env) {
  const value = { adb: env.ANDROID_HOME ? path.join(env.ANDROID_HOME, 'platform-tools', process.platform === 'win32' ? 'adb.exe' : 'adb') : 'adb' };
  const seen = new Set();
  for (let index = 0; index < args.length; index += 2) {
    const name = args[index], item = args[index + 1];
    if (!['--serial', '--adb'].includes(name) || seen.has(name) || typeof item !== 'string' || !item || item.length > 4096 || /[\u0000\r\n]/.test(item)) throw Error('invalid_capture_arguments');
    seen.add(name); value[name.slice(2)] = item;
  }
  if (!/^[A-Za-z0-9_.:-]{1,128}$/.test(value.serial ?? '')) throw Error('explicit_capture_serial_required');
  return Object.freeze(value);
}

export async function runCaptureColdRuntime(options) {
  const host = createEnrollmentHost(options), attempted = new Set();
  let receiver, stage = 'host_setup_failed';
  const report = { format: 'http-freekit-capture-cold-tcp', revision: 1, source: { commit: '0'.repeat(40), trackedDirty: true }, api: 0, clock: null,
    method: { invocation: parseCaptureColdInvocation('', null), receiversBefore: null, receiversAfter: null },
    cleanup: { forceStopExitCodes: [null, null, null], uninstallExitCodes: [null, null, null], packagesAbsent: false,
      ownedCommandsClosed: false, ownedCommandGroupsClosed: false, receivers: null }, problems: [], accepted: false };
  const requirePass = result => { if (!passed(result)) throw Error(stage); return result; };
  const problem = code => { const fixed = captureColdProblem(code); if (!report.problems.includes(fixed)) report.problems.push(fixed); };
  try {
    stage = 'source_unavailable';
    const commit = requirePass(await host.command('git', ['rev-parse', 'HEAD'])).output.trim();
    if (!/^[0-9a-f]{40}$/.test(commit)) throw Error(stage);
    report.source = { commit, trackedDirty: requirePass(await host.command('git', ['status', '--porcelain', '--untracked-files=no'])).output.trim() !== '' };
    if (report.source.trackedDirty) throw Error(stage);
    stage = 'device_unavailable';
    if (await host.state() !== 'device') throw Error(stage);
    report.api = Number(requirePass(await host.adb(['shell', 'getprop', 'ro.build.version.sdk'])).output.trim());
    if (report.api !== 26) throw Error(stage);
    stage = 'clock_outside_bound';
    const before = Date.now(), clockResult = requirePass(await host.adb(['shell', 'date', '+%s'], 5000)), after = Date.now();
    if (!/^[0-9]{10}$/.test(clockResult.output.trim())) throw Error(stage);
    const seconds = Number(clockResult.output.trim());
    report.clock = { deviceEpochSeconds: seconds, hostBeforeMillis: before, hostAfterMillis: after, roundTripMillis: after - before,
      lowerBoundMillis: seconds * 1000 - after, upperBoundMillis: seconds * 1000 + 999 - before };
    if (after < before || after - before > 2000 || report.clock.lowerBoundMillis < -2000 || report.clock.upperBoundMillis > 2000) throw Error(stage);
    stage = 'apk_build_failed';
    const tasks = ['--no-daemon', '--console=plain', ':capture-runtime:assembleDebug', ':capture-runtime:assembleDebugAndroidTest', ':capture-traffic:assembleDebug'];
    requirePass(await host.command(process.platform === 'win32' ? process.env.ComSpec ?? 'cmd.exe' : './gradlew',
      process.platform === 'win32' ? ['/d', '/s', '/c', 'gradlew.bat ' + tasks.join(' ')] : tasks, 900000));
    const apks = packages.map(([directory, applicationId]) => {
      const metadata = path.join(root, directory, 'output-metadata.json');
      if (fs.statSync(metadata).size > 65536) throw Error(stage);
      const value = JSON.parse(fs.readFileSync(metadata, 'utf8'));
      if (value.applicationId !== applicationId || value.elements?.length !== 1 || !/^[A-Za-z0-9_.-]+\.apk$/.test(value.elements[0].outputFile)) throw Error(stage);
      return path.join(root, directory, value.elements[0].outputFile);
    });
    const signer = path.join(process.env.ANDROID_HOME ?? '', 'build-tools/36.0.0', process.platform === 'win32' ? 'apksigner.bat' : 'apksigner');
    const digests = [];
    for (const apk of apks) {
      if (process.platform === 'win32' && /["%\r\n]/.test(signer + apk)) throw Error(stage);
      const result = requirePass(await host.command(process.platform === 'win32' ? process.env.ComSpec ?? 'cmd.exe' : signer,
        process.platform === 'win32' ? ['/d', '/s', '/c', `"${signer}" verify --print-certs "${apk}"`] : ['verify', '--print-certs', apk], 30000));
      const found = [...result.output.matchAll(/^Signer #1 certificate SHA-256 digest: ([0-9a-f]{64})\r?$/gm)];
      if (found.length !== 1) throw Error(stage); digests.push(found[0][1]);
    }
    if (new Set(digests).size !== 1) throw Error(stage);
    for (const [index, [, name]] of packages.entries()) {
      stage = 'package_already_present';
      if (requirePass(await host.adb(['shell', 'pm', 'list', 'packages', name])).output.trim()) throw Error(stage);
      stage = 'apk_install_failed'; attempted.add(index);
      const installed = requirePass(await host.adb(['install', '-t', apks[index]], 60000));
      if (installed.output.trim().split(/\r?\n/).at(-1) !== 'Success') throw Error(stage);
    }
    stage = 'host_setup_failed';
    const component = 'com.httpfreekit.capturetest.test/androidx.test.runner.AndroidJUnitRunner';
    const runners = requirePass(await host.adb(['shell', 'pm', 'list', 'instrumentation', 'com.httpfreekit.capturetest'])).output;
    if (!runners.split(/\r?\n/).some(line => line.startsWith('instrumentation:' + component + ' (target=com.httpfreekit.capturetest)'))) throw Error(stage);
    stage = 'fixture_setup_failed'; receiver = await createCaptureFixture();
    if (host.controller.signal.aborted) throw Error('research_cancelled');
    report.method.receiversBefore = receiver.snapshot();
    const result = await host.adb(['shell', 'am', 'instrument', '-w', '-r', '-e', 'class', captureColdClass + '#' + captureColdMethod,
      '-e', 'directPort', String(receiver.ports.direct), component], 90000);
    report.method.invocation = parseCaptureColdInvocation(result.output, result);
    report.method.receiversAfter = receiver.snapshot();
  } catch (failure) { problem(failure?.message === 'research_cancelled' ? failure.message : stage); }
  finally {
    for (const [index, [, name]] of packages.entries()) {
      if (!attempted.has(index)) continue;
      try {
        const stopped = await host.adb(['shell', 'am', 'force-stop', name], 10000, {}, true);
        report.cleanup.forceStopExitCodes[index] = stopped.code;
        if (!passed(stopped)) problem('cleanup_incomplete');
      } catch { problem('cleanup_incomplete'); }
      try {
        const removed = await host.adb(['uninstall', name], 60000, {}, true);
        report.cleanup.uninstallExitCodes[index] = removed.code;
        if (!passed(removed) || removed.output.trim() !== 'Success') problem('cleanup_incomplete');
      } catch { problem('cleanup_incomplete'); }
    }
    if (attempted.size === 3) {
      report.cleanup.packagesAbsent = true;
      for (const [, name] of packages) {
        try {
          const listed = await host.adb(['shell', 'pm', 'list', 'packages', name], 10000, {}, true);
          if (!passed(listed) || listed.output.trim()) report.cleanup.packagesAbsent = false;
          const script = `/system/bin/pidof ${name} >/dev/null; status=$?; if [ "$status" -eq 1 ]; then echo CAPTURE_ABSENT; else exit 1; fi`;
          const absent = await host.adb(['shell', '-T', 'sh', '-c', quote(script)], 10000, {}, true);
          if (!passed(absent) || absent.output.trim() !== 'CAPTURE_ABSENT') report.cleanup.packagesAbsent = false;
        } catch { report.cleanup.packagesAbsent = false; }
      }
    }
    if (receiver) { try { report.cleanup.receivers = await receiver.close(); } catch { report.cleanup.receivers = receiver.snapshot(); problem('cleanup_incomplete'); } }
    report.cleanup.ownedCommandsClosed = host.commands.every(result => result.closeObserved);
    report.cleanup.ownedCommandGroupsClosed = host.commands.every(result => result.processGroupClosed);
    if (!report.cleanup.ownedCommandsClosed || !report.cleanup.ownedCommandGroupsClosed) problem('cleanup_incomplete');
    host.dispose();
  }
  report.accepted = captureColdReportAccepted(report);
  return report;
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  try {
    const report = await runCaptureColdRuntime(captureColdOptions(process.argv.slice(2)));
    const directory = path.join(root, 'build/reports/capture-cold-tcp'); fs.mkdirSync(directory, { recursive: true });
    const json = JSON.stringify(report, null, 2) + '\n', xml = captureColdXml(report);
    if (Buffer.byteLength(json) > 131072 || Buffer.byteLength(xml) > 65536) throw Error('capture_report_bound');
    fs.writeFileSync(path.join(directory, 'runtime.json'), json); fs.writeFileSync(path.join(directory, 'TEST-capture-cold-tcp.xml'), xml);
    console.log(`Cold TCP comparison ${report.accepted ? 'complete' : 'incomplete'} (${report.method.invocation.state === 'passed' ? 1 : 0}/1).`);
    process.exitCode = report.accepted ? 0 : 1;
  } catch { console.error('Cold TCP comparison setup failed.'); process.exitCode = 1; }
}
