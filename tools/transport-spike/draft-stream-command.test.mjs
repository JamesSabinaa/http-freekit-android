import test from 'node:test';
import assert from 'node:assert/strict';
import { inspect } from 'node:util';
import { runDraftCommand as run } from './draft-stream-command.mjs';

test('actual child exit and pipe closure precede return; captured bytes are not default diagnostics', async () => {
  const result = await run(process.execPath, ['-e', 'process.stdout.write("PRIVATE_STDOUT");process.stderr.write("PRIVATE_STDERR")']);
  assert.equal(result.code, 0); assert.equal(result.closeObserved, true); assert.equal(result.reason, null);
  assert.equal(result.output, 'PRIVATE_STDOUT'); assert.equal(result.stderr.toString(), 'PRIVATE_STDERR');
  assert.doesNotMatch(JSON.stringify(result) + inspect(result), /PRIVATE_/);
});
test('a nonzero real exit is preserved without printing its stderr', async () => {
  const result = await run(process.execPath, ['-e', 'process.stderr.write("PRIVATE_FAILURE");process.exitCode=7']);
  assert.equal(result.code, 7); assert.equal(result.closeObserved, true);
  assert.doesNotMatch(JSON.stringify(result), /PRIVATE_FAILURE/);
});
test('an actual long-running child is terminated and joined at its deadline', { timeout: 15000 }, async () => {
  const result = await run(process.execPath, ['-e', 'setInterval(()=>{},100)'], { timeoutMillis: 200 });
  assert.equal(result.reason, 'owned_child_timeout'); assert.equal(result.closeObserved, true);
  assert.ok(result.code !== 0 || result.signal !== null);
});
test('output is capped and an overflowing child is joined rather than abandoned', { timeout: 15000 }, async () => {
  const result = await run(process.execPath, ['-e', 'process.stdout.write("x".repeat(200000));setInterval(()=>{},100)'], { maxOutputBytes: 1024 });
  assert.equal(result.reason, 'instrumentation_output_limit'); assert.equal(result.closeObserved, true);
  assert.ok(Buffer.byteLength(result.output) <= 1024);
});
test('cancellation joins the owned process and pre-aborted input never launches one', { timeout: 15000 }, async () => {
  const controller = new AbortController();
  const pending = run(process.execPath, ['-e', 'setInterval(()=>{},100)'], { abortSignal: controller.signal });
  controller.abort();
  const result = await pending;
  assert.equal(result.reason, 'research_run_cancelled'); assert.equal(result.closeObserved, true);
  await assert.rejects(run(process.execPath, [], { abortSignal: controller.signal }), /^Error: research_run_cancelled$/);
});
test('spawn failures are static and configuration errors do not launch commands', async () => {
  const result = await run('freekit-command-that-does-not-exist', []);
  assert.equal(result.spawnError, 'ENOENT'); assert.equal(result.reason, 'owned_child_spawn_failed'); assert.equal(result.closeObserved, true);
  await assert.rejects(run(process.execPath, [], { timeoutMillis: 0 }), /^Error: invalid_command_configuration$/);
  await assert.rejects(run(process.execPath, [], { maxOutputBytes: 999999 }), /^Error: invalid_command_configuration$/);
});
