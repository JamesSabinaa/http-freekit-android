import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { inspect } from 'node:util';
import test from 'node:test';
import { runDraftCommand as run } from './draft-stream-command.mjs';

test('private copied stdin reaches a real child and joins its input/process/stdio', async () => {
  const input = Buffer.from('PRIVATE_ENROLLMENT_INPUT');
  const expected = createHash('sha256').update(input).digest('hex');
  const pending = run(process.execPath, ['-e',
    'const {createHash}=require("node:crypto");const h=createHash("sha256");process.stdin.on("data",b=>h.update(b));process.stdin.on("end",()=>process.stdout.write(h.digest("hex")))'],
  { stdinBytes: input });
  input.fill(0);
  const result = await pending;
  assert.equal(result.code, 0);
  assert.equal(result.reason, null);
  assert.equal(result.closeObserved, true);
  assert.equal(result.processGroupClosed, true);
  assert.equal(result.inputFinished, true);
  assert.equal(result.inputClosed, true);
  assert.equal(result.output, expected);
  assert.doesNotMatch(JSON.stringify(result) + inspect(result), /PRIVATE_ENROLLMENT_INPUT/);
});

test('stdin bounds and types reject before launch and empty explicit input closes cleanly', async () => {
  for (const stdinBytes of [Buffer.alloc(16385), 'PRIVATE_INPUT', null, true]) {
    await assert.rejects(run(process.execPath, [], { stdinBytes }), /^Error: invalid_command_configuration$/);
  }
  const result = await run(process.execPath, ['-e', 'process.stdin.resume();process.stdin.on("end",()=>process.stdout.write("closed"))'],
    { stdinBytes: Buffer.alloc(0) });
  assert.equal(result.reason, null);
  assert.equal(result.output, 'closed');
  assert.equal(result.inputBytes, 0);
  assert.equal(result.inputClosed, true);
});

test('a live bounded observer can trigger host action before child completion without deadlock', async () => {
  const controller = new AbortController();
  let observed = '';
  const result = await run(process.execPath, ['-e',
    'process.stdout.write("phase-ready\\n");setInterval(()=>{},100)'],
  { abortSignal: controller.signal, onStdoutChunk(chunk) {
    observed += chunk.toString('ascii');
    if (observed.includes('phase-ready\n')) controller.abort();
  } });
  assert.equal(observed, 'phase-ready\n');
  assert.equal(result.reason, 'research_run_cancelled');
  assert.equal(result.closeObserved, true);
  assert.equal(result.processGroupClosed, true);
});

test('observer mutations do not alter retained output and observer exceptions remain fixed', async () => {
  const copied = await run(process.execPath, ['-e', 'process.stdout.write("safe")'],
    { onStdoutChunk(chunk) { chunk.fill(0); } });
  assert.equal(copied.output, 'safe');
  const failed = await run(process.execPath, ['-e', 'process.stdout.write("ready");setInterval(()=>{},100)'],
    { onStdoutChunk() { throw Error('PRIVATE_OBSERVER_CAUSE'); } });
  assert.equal(failed.reason, 'owned_child_observer_failed');
  assert.equal(failed.closeObserved, true);
  assert.doesNotMatch(JSON.stringify(failed) + inspect(failed), /PRIVATE_OBSERVER_CAUSE/);
});

test('asynchronous observer return is refused and joined without unhandled private rejection', async () => {
  const result = await run(process.execPath, ['-e', 'process.stdout.write("ready");setInterval(()=>{},100)'],
    { onStdoutChunk() { return Promise.reject(Error('PRIVATE_ASYNC_CAUSE')); } });
  assert.equal(result.reason, 'owned_child_observer_failed');
  assert.equal(result.closeObserved, true);
  assert.equal(result.processGroupClosed, true);
  assert.doesNotMatch(JSON.stringify(result) + inspect(result), /PRIVATE_ASYNC_CAUSE/);
});

test('private stdin and a live observer retain output-overflow cleanup and hide raw diagnostics', async () => {
  const result = await run(process.execPath, ['-e',
    'process.stdin.resume();process.stdout.write("PRIVATE".repeat(50000));setInterval(()=>{},100)'],
  { stdinBytes: Buffer.from('PRIVATE_STDIN'), maxOutputBytes: 1024, onStdoutChunk() {
    throw Error('overflow chunks must not reach the observer');
  } });
  assert.equal(result.reason, 'instrumentation_output_limit');
  assert.equal(result.inputClosed, true);
  assert.equal(result.closeObserved, true);
  assert.ok(Buffer.byteLength(result.output) <= 1024);
  assert.doesNotMatch(JSON.stringify(result) + inspect(result), /PRIVATE/);
});

test('deadline and cancellation close the private input pipe even when a child never reads it', async () => {
  const result = await run(process.execPath, ['-e', 'setInterval(()=>{},100)'],
    { stdinBytes: Buffer.alloc(16384, 9), timeoutMillis: 200 });
  assert.equal(result.reason, 'owned_child_timeout');
  assert.equal(result.inputClosed, true);
  assert.equal(result.closeObserved, true);
  assert.equal(result.processGroupClosed, true);
});

test('pre-aborted private input and invalid observers never launch a command', async () => {
  const controller = new AbortController();
  controller.abort();
  await assert.rejects(run(process.execPath, [], { stdinBytes: Buffer.from('PRIVATE'), abortSignal: controller.signal }),
    /^Error: research_run_cancelled$/);
  await assert.rejects(run(process.execPath, [], { onStdoutChunk: true }), /^Error: invalid_command_configuration$/);
});
