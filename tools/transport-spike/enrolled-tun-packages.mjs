import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { enrollmentPackage, enrollmentPassed, enrollmentShellQuote } from './enrollment-runtime-host.mjs';
import { enrollmentCommandObservation } from './enrollment-runtime-results.mjs';
import { parseEnrollmentJson } from '../../scripts/enrollment-corpus.mjs';

const root = fileURLToPath(new URL('../../', import.meta.url));
const runtime = 'com.httpfreekit.capturetest', traffic = 'com.httpfreekit.capturetraffic';
const control = runtime + '.permission.CONTROL_TRAFFIC';
const apks = [
  [enrollmentPackage, 'tools/transport-spike/android/build/outputs/apk/androidTest/debug'],
  [runtime, 'tools/capture-spike/runtime/build/outputs/apk/debug'],
  [traffic, 'tools/capture-spike/traffic/build/outputs/apk/debug'],
];
const fail = () => { throw Error('enrollment_fixture_failed'); };
const copy = value => JSON.parse(JSON.stringify(value));
function output(result, limit = 65536) {
  if (!result || !enrollmentPassed(result) || result.stderrBytes !== 0 || typeof result.output !== 'string' ||
      !result.output.isWellFormed() || Buffer.byteLength(result.output) > limit || /[^\x09\x0a\x0d\x20-\x7e]/.test(result.output)) fail();
  return result.output;
}
function listed(result, name) {
  const text = output(result).trim();
  if (!text) return false;
  const lines = text.split(/\r?\n/);
  if (lines.length > 128 || lines.some(line => !/^package:[A-Za-z][A-Za-z0-9_]*(?:\.[A-Za-z][A-Za-z0-9_]*)+$/.test(line))) fail();
  return lines.includes('package:' + name);
}
function apkFiles() {
  return apks.map(([applicationId, relative]) => {
    const directory = path.join(root, relative), metadata = path.join(directory, 'output-metadata.json');
    const stat = fs.statSync(metadata);
    if (!stat.isFile() || stat.size < 1 || stat.size > 65536) fail();
    const value = parseEnrollmentJson(fs.readFileSync(metadata));
    const filename = value?.elements?.[0]?.outputFile;
    if (value.applicationId !== applicationId || !Array.isArray(value.elements) || value.elements.length !== 1 ||
        typeof filename !== 'string' || filename.length > 128 || /^[A-Za-z0-9_.-]+\.apk$/.exec(filename)?.[0] !== filename) fail();
    return path.join(directory, filename);
  });
}
// AOSP Android8 Settings.java dumpPackageLPr/dumpInstallPermissionsLPr emits these
// package-scoped install grants. This is not the unsupported `pm check-permission`.
// https://android.googlesource.com/platform/frameworks/base/+/android-8.0.0_r1/services/core/java/com/android/server/pm/Settings.java
function controlGranted(result) {
  const lines = output(result).split(/\r?\n/);
  if (lines.length > 2048) fail();
  const headers = lines.map((line, index) => ({ line, index })).filter(({ line }) => /^\s*Package \[/.test(line));
  if (headers.length !== 1 || !/^  Package \[com\.httpfreekit\.interop\.test\] \([0-9a-fA-F]+\):$/.test(headers[0].line)) fail();
  let section = false, sections = 0, grants = 0;
  for (const line of lines.slice(headers[0].index + 1)) {
    if (!line.trim()) continue;
    const indent = line.length - line.trimStart().length;
    if (indent <= 2) break;
    if (line === '    install permissions:') { section = true; sections++; continue; }
    if (indent <= 4) section = false;
    if (section && line.trimStart().startsWith(control + ':')) {
      if (!/^      com\.httpfreekit\.capturetest\.permission\.CONTROL_TRAFFIC: granted=true(?:, flags=\[[\x20-\x7e]*\])?$/.test(line)) fail();
      grants++;
    }
  }
  return sections === 1 && grants === 1;
}

/** Owns only the two fixed absent-before-use extras; the shared host owns interop. */
export function createEnrolledTunPackageOwner(host) {
  const packages = [runtime, traffic].map(name => ({ package: name, initiallyAbsent: false, installAttempted: false,
    installed: false, installCommand: null, forceStopCommand: null, uninstallCommand: null,
    uninstallConfirmed: false, absentAfterCleanup: false }));
  const state = { sameSigner: false, controlTrafficGranted: false, packages,
    permissions: { mode: null, interopLocalNetwork: null, trafficLocalNetwork: null, interopNotification: null } };
  const owned = new Set(), unjoinedInstalls = new Set();
  let preparing, attempted = false, closing = false, cleaning, cleanupFailed = false;
  const snapshot = () => copy(state);
  const available = () => { if (closing) fail(); };
  const presence = async (name, cleanup = false) => listed(await host.adb(['shell', 'pm', 'list', 'packages', name], 10000, { maxOutputBytes: 65536 }, cleanup), name);
  return Object.freeze({ snapshot,
    async prepare(api) {
      if (![26, 37].includes(api) || attempted || preparing || closing) fail();
      attempted = true;
      preparing = (async () => {
        try {
          if (await host.state() !== 'device') fail();
          const tasks = ['--no-daemon', '--console=plain', ':transport-interop:assembleDebugAndroidTest', ':capture-runtime:assembleDebug', ':capture-traffic:assembleDebug'];
          const built = await host.command(process.platform === 'win32' ? process.env.ComSpec ?? 'cmd.exe' : './gradlew',
            process.platform === 'win32' ? ['/d', '/s', '/c', 'gradlew.bat ' + tasks.join(' ')] : tasks, 900000);
          if (!enrollmentPassed(built)) fail();
          available();
          const files = apkFiles(), sdk = process.env.ANDROID_HOME;
          if (typeof sdk !== 'string' || !path.isAbsolute(sdk) || /[\0\r\n]/.test(sdk)) fail();
          const signer = path.join(sdk, 'build-tools/36.0.0', process.platform === 'win32' ? 'apksigner.bat' : 'apksigner');
          const digests = [];
          for (const apk of files) {
            available();
            if (process.platform === 'win32' && /["%\r\n]/.test(signer + apk)) fail();
            const verified = await host.command(process.platform === 'win32' ? process.env.ComSpec ?? 'cmd.exe' : signer,
              process.platform === 'win32' ? ['/d', '/s', '/c', `"${signer}" verify --print-certs "${apk}"`] : ['verify', '--print-certs', apk], 30000);
            const lines = output(verified).split(/\r?\n/).filter(line => /^Signer #[0-9]+ certificate SHA-256 digest:/.test(line));
            if (lines.length !== 1 || !/^Signer #1 certificate SHA-256 digest: [0-9a-fA-F]{64}$/.test(lines[0])) fail();
            digests.push(lines[0].slice(-64).toLowerCase());
          }
          if (new Set(digests).size !== 1) fail();
          state.sameSigner = true;
          for (const item of packages) {
            available();
            if (await presence(item.package)) fail();
            item.initiallyAbsent = true;
          }
          for (const [index, item] of packages.entries()) {
            available(); item.installAttempted = true; owned.add(item.package);
            let installed;
            try { installed = await host.adb(['install', '-t', files[index + 1]], 60000); }
            catch { unjoinedInstalls.add(item.package); throw Error('enrollment_fixture_failed'); }
            if (!installed.closeObserved || !installed.processGroupClosed) unjoinedInstalls.add(item.package);
            item.installCommand = enrollmentCommandObservation(installed);
            if (output(installed).trim().split(/\r?\n/).at(-1) !== 'Success' || !(await presence(item.package))) fail();
            item.installed = true;
          }
          available();
          state.controlTrafficGranted = controlGranted(await host.adb(['shell', 'dumpsys', 'package', enrollmentPackage], 10000, { maxOutputBytes: 65536 }));
          if (!state.controlTrafficGranted) fail();
          state.permissions.mode = api === 37 ? 'owned_ci_grant' : 'not_required';
          if (api === 37) for (const [name, permission, key] of [
            [enrollmentPackage, 'android.permission.ACCESS_LOCAL_NETWORK', 'interopLocalNetwork'],
            [traffic, 'android.permission.ACCESS_LOCAL_NETWORK', 'trafficLocalNetwork'],
            [enrollmentPackage, 'android.permission.POST_NOTIFICATIONS', 'interopNotification'],
          ]) {
            available(); const result = await host.adb(['shell', 'pm', 'grant', name, permission]);
            state.permissions[key] = enrollmentCommandObservation(result); output(result);
          }
          available(); return snapshot();
        } catch { throw Error('enrollment_fixture_failed'); }
      })();
      try { return await preparing; } finally { preparing = undefined; }
    },
    async cleanup() {
      closing = true;
      if (cleaning) return cleaning;
      cleaning = (async () => {
        await preparing?.catch(() => {});
        for (const item of packages) {
          if (!item.installAttempted || item.absentAfterCleanup) continue;
          if (owned.has(item.package)) {
            try {
              const stopped = await host.adb(['shell', 'am', 'force-stop', item.package], 10000, {}, true);
              item.forceStopCommand = enrollmentCommandObservation(stopped); output(stopped);
            } catch { cleanupFailed = true; }
            try {
              const removed = await host.adb(['uninstall', item.package], 60000, {}, true);
              item.uninstallCommand = enrollmentCommandObservation(removed);
              item.uninstallConfirmed = enrollmentPassed(removed) && typeof removed.output === 'string' && removed.output.trim() === 'Success';
              if (item.uninstallConfirmed) owned.delete(item.package); else cleanupFailed = true;
              output(removed);
            } catch { cleanupFailed = true; }
          }
          let packageAbsent = false, processAbsent = false;
          try { packageAbsent = !(await presence(item.package, true)); } catch { cleanupFailed = true; }
          try {
            const script = `/system/bin/pidof ${item.package} >/dev/null; status=$?; if [ "$status" -eq 1 ]; then echo TUN_PACKAGE_ABSENT; else exit 1; fi`;
            processAbsent = output(await host.adb(['shell', '-T', 'sh', '-c', enrollmentShellQuote(script)], 10000, {}, true)).trim() === 'TUN_PACKAGE_ABSENT';
          } catch { cleanupFailed = true; }
          // An unjoined install can still mutate the device after an absence probe.
          item.absentAfterCleanup = packageAbsent && processAbsent && !unjoinedInstalls.has(item.package);
          if (item.absentAfterCleanup) owned.delete(item.package); else cleanupFailed = true;
        }
        return { failed: cleanupFailed, snapshot: snapshot() };
      })();
      try { return await cleaning; } finally { cleaning = undefined; }
    },
  });
}
