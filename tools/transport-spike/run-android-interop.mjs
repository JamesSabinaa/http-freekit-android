// Run from the repository root. Public peer metadata is the only instrumentation input.
import { execFileSync, spawn } from 'node:child_process';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { expectedTests, startPeer } from './android-peer.mjs';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../..');
const options = { adb: process.env.ANDROID_HOME ? path.join(process.env.ANDROID_HOME, 'platform-tools', process.platform === 'win32' ? 'adb.exe' : 'adb') : 'adb', openssl: process.env.OPENSSL_BIN ?? 'openssl' };
for (let index = 2; index < process.argv.length; index += 2) {
  const name = process.argv[index];
  if (!['--serial', '--adb', '--openssl'].includes(name) || !process.argv[index + 1]) throw Error('Usage: node tools/transport-spike/run-android-interop.mjs --serial SERIAL [--adb PATH] [--openssl PATH]');
  options[name.slice(2)] = process.argv[index + 1];
}
if (!options.serial || !/^[A-Za-z0-9_.:-]{1,128}$/.test(options.serial)) throw Error('An explicit adb --serial is required');
const adb = args => execFileSync(options.adb, ['-s', options.serial, ...args], { timeout: 10000, maxBuffer: 65536, encoding: 'utf8' }).trim();
const mappings = [];
let peer;
let gradle;
let stopping = false;
async function stopGradle() {
  if (!gradle?.pid || gradle.exitCode !== null) return;
  if (process.platform === 'win32') {
    // Only this wrapper's process tree; no global Gradle/Java termination.
    execFileSync('taskkill.exe', ['/PID', String(gradle.pid), '/T', '/F'], { timeout: 10000, stdio: 'ignore', windowsHide: true });
  } else {
    try { process.kill(-gradle.pid, 'SIGTERM'); } catch (failure) { if (failure.code !== 'ESRCH') throw failure; }
    await new Promise(resolve => {
      const timer = setTimeout(resolve, 3000);
      gradle.once('exit', () => { clearTimeout(timer); resolve(); });
    });
    // Also stop descendants that outlived the wrapper in this owned process group.
    try { process.kill(-gradle.pid, 'SIGKILL'); } catch (failure) { if (failure.code !== 'ESRCH') throw failure; }
  }
}
async function cleanup() {
  const failures = [];
  for (const mapping of mappings.splice(0).reverse()) {
    try { adb(['reverse', '--remove', `tcp:${mapping}`]); } catch { failures.push('Could not remove owned adb reverse mapping'); }
  }
  try { await peer?.close(); } catch { failures.push('Could not clean ephemeral research peer'); }
  if (failures.length) throw Error(failures.join('; '));
}
for (const signal of ['SIGINT', 'SIGTERM']) process.once(signal, () => {
  if (stopping) return;
  stopping = true;
  stopGradle().finally(() => cleanup().finally(() => process.exit(1)));
});
function xmlFiles(directory) {
  if (!fs.existsSync(directory)) return [];
  return fs.readdirSync(directory, { withFileTypes: true }).flatMap(entry => entry.isDirectory()
    ? xmlFiles(path.join(directory, entry.name)) : entry.name.endsWith('.xml') ? [path.join(directory, entry.name)] : []);
}
try {
  if (adb(['get-state']) !== 'device') throw Error('The selected Android device is unavailable');
  peer = await startPeer({ openssl: options.openssl });
  const args = ['--no-daemon', '--console=plain', ':transport-interop:connectedDebugAndroidTest'];
  const metadata = { ...peer.metadata };
  for (const key of ['enrollmentPort', 'webSocketPort']) {
    const mapped = adb(['reverse', '--no-rebind', 'tcp:0', `tcp:${metadata[key]}`]);
    if (!/^[0-9]{1,5}$/.test(mapped) || Number(mapped) < 1 || Number(mapped) > 65535) throw Error('adb did not allocate a valid reverse port');
    mappings.push(mapped);
    metadata[key] = mapped;
  }
  for (const [name, value] of Object.entries(metadata)) {
    if (!/^[A-Za-z0-9_-]+$/.test(String(value))) throw Error('Invalid public fixture metadata');
    args.push(`-Pinterop.${name}=${value}`);
  }
  const started = Date.now();
  console.log('Research peer ready on two owned adb reverse mappings; starting four Android cases.');
  const command = process.platform === 'win32' ? process.env.ComSpec ?? 'cmd.exe' : './gradlew';
  const commandArgs = process.platform === 'win32' ? ['/d', '/s', '/c', `gradlew.bat ${args.join(' ')}`] : args;
  await new Promise((resolve, reject) => {
    gradle = spawn(command, commandArgs, { cwd: root, env: { ...process.env, ANDROID_SERIAL: options.serial }, stdio: 'inherit', detached: process.platform !== 'win32', windowsHide: true });
    const deadline = setTimeout(() => {
      stopGradle().then(() => reject(Error('Android research task exceeded 15 minutes')), reject);
    }, 15 * 60 * 1000);
    gradle.once('error', error => { clearTimeout(deadline); reject(error); });
    gradle.once('exit', code => { clearTimeout(deadline); code === 0 ? resolve() : reject(Error(`Android research task failed (${code})`)); });
  });
  const results = path.join(root, 'tools/transport-spike/android/build/outputs/androidTest-results/connected/debug');
  const cases = [];
  const files = xmlFiles(results).filter(file => fs.statSync(file).mtimeMs >= started - 2000);
  if (!files.length) throw Error('Missing fresh Android instrumentation XML');
  for (const file of files) {
    const xml = fs.readFileSync(file, 'utf8');
    if (/<(?:failure|error|skipped)\b/.test(xml) || /\b(?:failures|errors|skipped)="[1-9][0-9]*"/.test(xml)) throw Error('Instrumentation reports a failure or skip');
    for (const match of xml.matchAll(/<testcase\b([^>]*)>/g)) {
      const name = /\bname="([^"]+)"/.exec(match[1])?.[1];
      const className = /\bclassname="([^"]+)"/.exec(match[1])?.[1];
      if (className !== 'com.httpfreekit.interop.AndroidNodeInteropTest' || !expectedTests.includes(name)) throw Error('Unexpected instrumentation case');
      cases.push(name);
    }
  }
  if (cases.length !== 4 || new Set(cases).size !== 4 || expectedTests.some(name => !cases.includes(name))) throw Error('Expected exactly four research instrumentation cases');
  console.log('Confirmed four Android-to-Node cases, zero failures/errors/skips.');
} catch (failure) {
  // Do not include child-process stderr, request bytes, private paths, or certificate material.
  const reason = failure.code ?? (failure.status !== undefined ? `host command failed (${failure.status})` : failure.message.split('\n')[0]);
  console.error(`Android-to-Node research failed: ${reason}`);
  process.exitCode = 1;
} finally {
  try { await cleanup(); } catch (failure) { console.error(failure.message); process.exitCode = 1; }
}
