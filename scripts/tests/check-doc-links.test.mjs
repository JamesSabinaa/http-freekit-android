import assert from 'node:assert/strict';
import fs from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { after, test } from 'node:test';
import { checkDocumentation } from '../check-doc-links.mjs';

const roots = [];
async function fixture(files) {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), 'freekit-doc-links-'));
  roots.push(root);
  for (const [name, contents] of Object.entries(files)) {
    const location = path.join(root, name);
    await fs.mkdir(path.dirname(location), { recursive: true });
    await fs.writeFile(location, contents);
  }
  return root;
}

after(async () => {
  const temporaryRoot = await fs.realpath(os.tmpdir());
  for (const root of roots) {
    const resolved = await fs.realpath(root);
    assert.equal(path.dirname(resolved), temporaryRoot);
    assert.ok(path.basename(resolved).startsWith('freekit-doc-links-'));
    await fs.rm(resolved, { recursive: true, force: true });
  }
});

test('resolves relative/root paths, encoded spaces, parentheses, and reference destinations', async () => {
  const root = await fixture({
    'README.md': '[guide](docs/guide.md#setup) ![image](assets/a(b).svg) [spaced](<docs/a b.md>) [encoded](docs/a%20b.md)\n[reference]: /docs/guide.md#setup "Guide"\n',
    'docs/guide.md': '# Setup\n',
    'docs/a b.md': '# Space\n[home](../README.md)\n',
    'assets/a(b).svg': '<svg/>',
  });
  const result = await checkDocumentation(root);
  assert.equal(result.checkedLinks, 6);
  assert.deepEqual(result.failures, []);
});

test('reports missing local files and missing Markdown anchors with source lines', async () => {
  const root = await fixture({ 'README.md': '# Start\n[missing](missing.md)\n[anchor](#absent)\n' });
  const result = await checkDocumentation(root);
  assert.deepEqual(result.failures.map(({ line, reason }) => ({ line, reason })), [
    { line: 2, reason: 'target not found' },
    { line: 3, reason: 'Markdown heading or explicit anchor not found' },
  ]);
});

test('ignores fenced examples, inline code, escaped link syntax, and external schemes', async () => {
  const root = await fixture({ 'README.md': [
    'A sibling path is documented as `../http-freekit/README.md`.',
    '`[example](missing.md)`',
    '\\[escaped](missing.md)',
    '```powershell',
    '[example](missing.md)',
    '```',
    '~~~text',
    '[example](missing.md)',
    '~~~',
    '[web](https://example.invalid/a) [mail](mailto:user@example.invalid) [app](app://example) [protocol](//example.invalid/a)',
  ].join('\n') });
  assert.deepEqual(await checkDocumentation(root), { documents: 1, checkedLinks: 0, failures: [] });
});

test('does not scan generated directories or nested Git worktrees', async () => {
  const root = await fixture({
    'README.md': '# Root\n',
    'build/broken.md': '[missing](missing.md)',
    'app/build/broken.md': '[missing](missing.md)',
    'app/.cxx/debug/broken.md': '[missing](missing.md)',
    'app/.externalNativeBuild/broken.md': '[missing](missing.md)',
    'node_modules/package/broken.md': '[missing](missing.md)',
    '.gradle/broken.md': '[missing](missing.md)',
    'dist/broken.md': '[missing](missing.md)',
    'worktree/.git': 'gitdir: ignored',
    'worktree/broken.md': '[missing](missing.md)',
  });
  assert.deepEqual(await checkDocumentation(root), { documents: 1, checkedLinks: 0, failures: [] });
});

test('handles duplicate heading slugs and explicit HTML anchors', async () => {
  const root = await fixture({ 'README.md': '# Repeat\n# Repeat\n<a id="custom"></a>\n[first](#repeat) [second](#repeat-1) [custom](#custom)\n' });
  const result = await checkDocumentation(root);
  assert.equal(result.checkedLinks, 3);
  assert.deepEqual(result.failures, []);
});

test('rejects malformed URL escapes without crashing', async () => {
  const root = await fixture({ 'README.md': '[broken](file%ZZ.md)\n' });
  const result = await checkDocumentation(root);
  assert.equal(result.failures[0].reason, 'invalid percent encoding');
});

test('rejects actual Markdown links escaping the checkout', async () => {
  const outside = await fixture({ 'outside.md': '# Outside\n' });
  const root = await fixture({ 'README.md': `[outside](../${path.basename(outside)}/outside.md)\n` });
  const result = await checkDocumentation(root);
  assert.equal(result.failures[0].reason, 'target leaves this repository');
});

test('checks the outer destination of linked images and skips incomplete link syntax', async () => {
  const root = await fixture({
    'README.md': '[![badge](badge.svg)](missing.md "Details")\n[unfinished](also-missing.md\n',
    'badge.svg': '<svg/>',
  });
  const result = await checkDocumentation(root);
  assert.equal(result.checkedLinks, 2);
  assert.deepEqual(result.failures.map(({ target, reason }) => ({ target, reason })), [
    { target: 'missing.md', reason: 'target not found' },
  ]);
});

test('the command exits unsuccessfully and reports a source line for broken links', async () => {
  const root = await fixture({ 'README.md': '# Guide\n[broken](missing.md)\n' });
  const command = spawnSync(process.execPath, [fileURLToPath(new URL('../check-doc-links.mjs', import.meta.url)), root], { encoding: 'utf8' });
  assert.equal(command.status, 1);
  assert.match(command.stderr, /README\.md:2: missing\.md: target not found/);
  assert.match(command.stdout, /1 failures/);
});
