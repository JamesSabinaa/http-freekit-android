import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { runDraftCommand } from './draft-stream-command.mjs';
import { createEnrolledTunAliasOwner, enrolledTunGateScript, publishEnrolledTunAcknowledgment } from './enrolled-tun-host.mjs';
import { enrolledTunAcknowledgment } from './enrolled-tun-descriptor.mjs';

const bash = process.platform === 'win32' ? 'C:/Program Files/Git/bin/bash.exe' : '/bin/bash';
const fakeIp = `#!/usr/bin/env bash
set -eu
printf '%s\\n' "$*" >> "$TEST_DIRECTORY/calls"
case "$*" in
  '-j -4 address show dev lo')
    if [ "$TEST_BAD_AFTER" = true ] && [ -f "$TEST_DIRECTORY/deleted" ] && [ ! -f "$TEST_DIRECTORY/after-bad-seen" ]; then
      touch "$TEST_DIRECTORY/after-bad-seen"; echo CANARY_PRIVATE; exit 0
    fi
    if [ "$TEST_BAD_VERIFY" = true ] && [ -f "$TEST_DIRECTORY/created" ] && [ ! -f "$TEST_DIRECTORY/bad-seen" ]; then
      touch "$TEST_DIRECTORY/bad-seen"; echo CANARY_PRIVATE; exit 0
    fi
    if [ -f "$TEST_DIRECTORY/created" ]; then
      printf '[{"ifname":"lo","addr_info":[{"family":"inet","local":"198.18.0.2","prefixlen":32}]}]'
    else printf '[{"ifname":"lo","addr_info":[{"family":"inet","local":"127.0.0.1","prefixlen":8}]}]'; fi ;;
  '-4 address add 198.18.0.2/32 dev lo')
    if [ "$TEST_CREATE_FAIL" = true ]; then exit 21; fi
    touch "$TEST_DIRECTORY/created" ;;
  '-4 address del 198.18.0.2/32 dev lo')
    if [ "$TEST_REMOVE_FAIL" = true ]; then exit 22; fi
    rm "$TEST_DIRECTORY/created"; touch "$TEST_DIRECTORY/deleted" ;;
  *) exit 91 ;;
esac
`;
const fakeCat = `#!/usr/bin/env bash
set -eu
if [ "$TEST_CAT_GATE" != true ]; then exec /bin/cat; fi
/bin/cat > "$TEST_DIRECTORY/input-buffer"
head -c 7 "$TEST_DIRECTORY/input-buffer"
echo entered > "$TEST_DIRECTORY/cat-entered"
for ((attempt=0; attempt<300; attempt++)); do
  if [ -e "$TEST_DIRECTORY/cat-release" ]; then exec tail -c +8 "$TEST_DIRECTORY/input-buffer"; fi
  sleep 0.01
done
exit 23
`;

async function fixture(options, action) {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'freekit-tun-host-'));
  const running = new Set();
  try {
    for (const [name, source] of Object.entries({ ip: fakeIp, cat: fakeCat,
      sudo: '#!/usr/bin/env bash\n[[ "$1" == -n && "$2" == ip ]] || exit 90\nshift\nexec "$@"\n',
      chmod: '#!/usr/bin/env bash\nif [[ "$TEST_CHMOD_FAIL" == true ]]; then exit 24; fi\nexec /bin/chmod "$@"\n' })) fs.writeFileSync(path.join(directory, name), source, { mode: 0o700 });
    const environment = { ...process.env, TEST_DIRECTORY: directory, TEST_BAD_VERIFY: String(options.badVerify ?? false),
      TEST_CREATE_FAIL: String(options.createFail ?? false), TEST_REMOVE_FAIL: String(options.removeFail ?? false),
      TEST_BAD_AFTER: String(options.badAfter ?? false),
      TEST_CAT_GATE: String(options.catGate ?? false), TEST_CHMOD_FAIL: String(options.chmodFail ?? false) };
    const setup = 'set -eu\nif command -v cygpath >/dev/null 2>&1; then TEST_DIRECTORY="$(cygpath -u "$TEST_DIRECTORY")"; fi\nexport TEST_DIRECTORY PATH="$TEST_DIRECTORY:$PATH"\n';
    const launch = (args, script, extras = {}) => {
      const task = runDraftCommand(bash, ['-c', setup + script, 'owned-tun-test', ...args], { cwd: directory,
        env: environment, timeoutMillis: 8000, maxOutputBytes: 65536, ...extras });
      running.add(task); task.finally(() => running.delete(task)).catch(() => {}); return task;
    };
    const command = (executable, args) => launch([executable, ...args], 'exec "$@"');
    const privateDirectory = path.join(directory, 'no_backup/draft-enrollment-research'); fs.mkdirSync(privateDirectory, { recursive: true, mode: 0o700 });
    const target = path.join(privateDirectory, 'tun-complete-v1.bin'), pending = path.join(privateDirectory, '.tun-complete-v1.pending');
    const gate = () => launch([], enrolledTunGateScript, { stdinBytes: Buffer.from(enrolledTunAcknowledgment.bytes) });
    await action({ directory, privateDirectory, target, pending, command, gate });
  } finally {
    fs.writeFileSync(path.join(directory, 'cat-release'), 'release');
    await Promise.allSettled([...running]);
    assert.equal(path.dirname(path.resolve(directory)), path.resolve(os.tmpdir()));
    assert.match(path.basename(directory), /^freekit-tun-host-/); fs.rmSync(directory, { recursive: true, force: true });
  }
}

test('C5 refuses an unsupported host before running any alias command', async () => {
  const owner = createEnrolledTunAliasOwner(() => { throw Error('A command must not run'); }, { platform: 'win32' });
  await assert.rejects(owner.prepare(), /enrollment_fixture_failed/);
  assert.equal(owner.snapshot().refusal, 'unsupported_platform'); assert.equal(owner.snapshot().created, false);
});

test('actual owned command children create, verify and remove only the fixed alias; repeated removal is inert', async () => {
  await fixture({}, async ({ command, directory }) => {
    const owner = createEnrolledTunAliasOwner(command, { platform: 'linux' });
    const before = await owner.prepare(); assert(before.initiallyAbsent && before.created && before.verified);
    assert.equal(fs.existsSync(path.join(directory, 'created')), true);
    const after = await owner.remove({ fixtureJoined: true }); assert(after.removed && after.absenceConfirmed && after.removalRequested);
    assert.equal(fs.existsSync(path.join(directory, 'created')), false);
    const calls = fs.readFileSync(path.join(directory, 'calls'), 'utf8'); await owner.remove({ fixtureJoined: true });
    assert.equal(fs.readFileSync(path.join(directory, 'calls'), 'utf8'), calls);
    for (const observed of Object.values(after.commands)) assert(observed.exitCode === 0 && observed.closeObserved && observed.processGroupClosed);
  });
});

test('a pre-existing alias is refused and never removed', async () => {
  await fixture({}, async ({ command, directory }) => {
    fs.writeFileSync(path.join(directory, 'created'), 'pre-existing');
    const owner = createEnrolledTunAliasOwner(command, { platform: 'linux' });
    await assert.rejects(owner.prepare()); await owner.remove({ fixtureJoined: true });
    assert.equal(owner.snapshot().refusal, 'alias_preexisting'); assert.equal(owner.snapshot().created, false);
    assert.equal(fs.readFileSync(path.join(directory, 'created'), 'utf8'), 'pre-existing');
    assert.equal(fs.readFileSync(path.join(directory, 'calls'), 'utf8').trim(), '-j -4 address show dev lo');
  });
});

test('concurrent alias cleanup calls share one actual deletion', async () => {
  await fixture({}, async ({ command, directory }) => {
    const owner = createEnrolledTunAliasOwner(command, { platform: 'linux' }); await owner.prepare();
    const results = await Promise.all([owner.remove({ fixtureJoined: true }), owner.remove({ fixtureJoined: true })]);
    assert(results.every(value => value.removed && value.absenceConfirmed));
    assert.equal(fs.readFileSync(path.join(directory, 'calls'), 'utf8').split('\n').filter(line => line.startsWith('-4 address del ')).length, 1);
  });
});

test('a successful deletion ends ownership even when its following state read fails; a replacement alias is untouched', async () => {
  await fixture({ badAfter: true }, async ({ command, directory }) => {
    const owner = createEnrolledTunAliasOwner(command, { platform: 'linux' }); await owner.prepare();
    await assert.rejects(owner.remove({ fixtureJoined: true }));
    assert.equal(owner.snapshot().commands.remove.exitCode, 0); assert.equal(owner.snapshot().absenceConfirmed, false);
    fs.writeFileSync(path.join(directory, 'created'), 'other-owner');
    await assert.rejects(owner.remove({ fixtureJoined: true }));
    assert.equal(fs.readFileSync(path.join(directory, 'created'), 'utf8'), 'other-owner');
    assert.equal(fs.readFileSync(path.join(directory, 'calls'), 'utf8').split('\n').filter(line => line.startsWith('-4 address del ')).length, 1);
  });
});

test('failed add never invents ownership, while failed verification retains ownership for actual cleanup', async () => {
  await fixture({ createFail: true }, async ({ command }) => {
    const owner = createEnrolledTunAliasOwner(command, { platform: 'linux' }); await assert.rejects(owner.prepare());
    const result = await owner.remove({ fixtureJoined: true }); assert.equal(result.created, false); assert.equal(result.commands.create.exitCode, 21);
  });
  await fixture({ badVerify: true }, async ({ command, directory }) => {
    const owner = createEnrolledTunAliasOwner(command, { platform: 'linux' }); await assert.rejects(owner.prepare());
    assert(owner.snapshot().created && !owner.snapshot().verified); assert.equal(owner.snapshot().refusal, 'alias_verify_failed');
    assert(!JSON.stringify(owner.snapshot()).includes('CANARY'));
    const result = await owner.remove({ fixtureJoined: true }); assert(result.removed && result.absenceConfirmed);
    assert.equal(fs.existsSync(path.join(directory, 'created')), false); assert.equal(result.refusal, 'alias_verify_failed');
  });
});

test('unjoined fixtures block alias removal; failed removal remains visible even after a valid state read', async () => {
  await fixture({ removeFail: true }, async ({ command, directory }) => {
    const owner = createEnrolledTunAliasOwner(command, { platform: 'linux' }); await owner.prepare();
    await assert.rejects(owner.remove({ fixtureJoined: false })); assert.equal(owner.snapshot().commands.remove, null);
    await assert.rejects(owner.remove({ fixtureJoined: true })); assert.equal(owner.snapshot().commands.remove.exitCode, 22);
    assert(!owner.snapshot().removed && !owner.snapshot().absenceConfirmed); assert(fs.existsSync(path.join(directory, 'created')));
  });
});

test('actual private gate is invisible during a partial write and atomically publishes only complete fixed bytes', async () => {
  await fixture({ catGate: true }, async ({ gate, directory, target, pending }) => {
    const operation = gate(), deadline = performance.now() + 5000;
    while (!fs.existsSync(path.join(directory, 'cat-entered')) && performance.now() < deadline) await new Promise(done => setTimeout(done, 10));
    assert(fs.existsSync(path.join(directory, 'cat-entered'))); assert.equal(fs.existsSync(target), false);
    assert.equal(fs.readFileSync(pending).length, 7);
    fs.writeFileSync(path.join(directory, 'cat-release'), 'release');
    const result = await operation; assert.equal(result.code, 0); assert(result.closeObserved && result.processGroupClosed && result.inputFinished && result.inputClosed);
    assert.equal(result.output.trim(), 'TUN_GATE_PUBLISHED'); assert.equal(result.stderrBytes, 0);
    assert.equal(fs.readFileSync(target, 'utf8'), enrolledTunAcknowledgment.bytes); assert.equal(fs.existsSync(pending), false);
    if (process.platform !== 'win32') assert.equal(fs.statSync(target).mode & 0o777, 0o600);
  });
});

test('existing final or pending gate files are never overwritten or deleted', async () => {
  for (const kind of ['target', 'pending']) await fixture({}, async value => {
    fs.writeFileSync(value[kind], 'existing'); const result = await value.gate();
    assert.notEqual(result.code, 0); assert.equal(fs.readFileSync(value[kind], 'utf8'), 'existing');
  });
});

test('a failure after the completed gate write removes only the owned pending inode and publishes no final file', async () => {
  await fixture({ chmodFail: true }, async ({ gate, target, pending }) => {
    const result = await gate(); assert.equal(result.code, 24); assert(result.closeObserved && result.processGroupClosed);
    assert.equal(fs.existsSync(target), false); assert.equal(fs.existsSync(pending), false);
  });
});

test('ADB gate adapter requires actual stdin completion and command/marker joins without retaining the gate bytes', async () => {
  const base = { code: 0, signal: null, reason: null, closeObserved: true, processGroupClosed: true, stderrBytes: 0,
    output: 'TUN_GATE_PUBLISHED\n', inputBytes: Buffer.byteLength(enrolledTunAcknowledgment.bytes), inputFinished: true, inputClosed: true };
  for (const changed of [{}, { code: 1 }, { inputClosed: false }, { inputBytes: 0 }, { processGroupClosed: false }, { stderrBytes: 1 }]) {
    const result = await publishEnrolledTunAcknowledgment({ async adb(args, timeout, options) {
      assert.equal(timeout, 10000); assert.equal(options.stdinBytes.toString(), enrolledTunAcknowledgment.bytes);
      assert(args.includes('run-as')); return { ...base, ...changed };
    } });
    assert.equal(result.published, Object.keys(changed).length === 0); assert(!JSON.stringify(result).includes('FREEKIT-C5'));
  }
});
