import fs from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const ignoredDirectories = new Set(['.git', '.gradle', '.kotlin', '.idea', '.cxx', '.externalNativeBuild', 'build', 'dist', 'node_modules']);

async function markdownFiles(root, directory = root) {
  const entries = await fs.readdir(directory, { withFileTypes: true });
  // A nested repository or worktree is not part of this checkout's documentation.
  if (directory !== root && entries.some(entry => entry.name === '.git')) return [];
  const files = [];
  for (const entry of entries) {
    if (entry.isSymbolicLink()) continue;
    const location = path.join(directory, entry.name);
    if (entry.isDirectory() && !ignoredDirectories.has(entry.name)) files.push(...await markdownFiles(root, location));
    else if (entry.isFile() && /\.md$/i.test(entry.name)) files.push(location);
  }
  return files.sort();
}

function withoutFences(source) {
  let fence;
  return source.split('\n').map(line => {
    if (fence) {
      const close = line.match(/^ {0,3}(`{3,}|~{3,})\s*\r?$/);
      if (close && close[1][0] === fence[0] && close[1].length >= fence.length) fence = undefined;
      return ' '.repeat(line.length);
    }
    const open = line.match(/^ {0,3}(`{3,}|~{3,})/);
    if (open) {
      fence = open[1];
      return ' '.repeat(line.length);
    }
    return line;
  }).join('\n');
}

function withoutInlineCode(source) {
  return source.replace(/(`+)([\s\S]*?)\1(?!`)/g, match => match.replace(/[^\n]/g, ' '));
}

function isEscaped(text, index) {
  let count = 0;
  while (index > 0 && text[--index] === '\\') count++;
  return count % 2 === 1;
}

function destinationAt(source, offset) {
  while (/\s/.test(source[offset] ?? '') && offset < source.length) offset++;
  if (source[offset] === '<') {
    const end = source.indexOf('>', offset + 1);
    return end < 0 ? undefined : { target: source.slice(offset + 1, end), end: end + 1 };
  }
  const start = offset;
  let nesting = 0;
  for (; offset < source.length; offset++) {
    const character = source[offset];
    if (isEscaped(source, offset)) continue;
    if (character === '(') nesting++;
    else if (character === ')') {
      if (nesting === 0) break;
      nesting--;
    } else if (/\s/.test(character) && nesting === 0) break;
  }
  return nesting === 0 ? { target: source.slice(start, offset), end: offset } : undefined;
}

function inlineLinkEnd(source, destinationEnd) {
  let offset = destinationEnd;
  while (/\s/.test(source[offset] ?? '') && offset < source.length) offset++;
  if (source[offset] === ')') return offset;
  // A title must be separated from its destination by whitespace.
  if (offset === destinationEnd || !['"', "'", '('].includes(source[offset])) return undefined;
  const close = source[offset] === '(' ? ')' : source[offset];
  offset++;
  while (offset < source.length && (source[offset] !== close || isEscaped(source, offset))) offset++;
  if (offset === source.length) return undefined;
  offset++;
  while (/\s/.test(source[offset] ?? '') && offset < source.length) offset++;
  return source[offset] === ')' ? offset : undefined;
}

function destinations(source) {
  const text = withoutInlineCode(withoutFences(source));
  const links = [];
  const brackets = [];
  for (let index = 0; index < text.length; index++) {
    if (isEscaped(text, index)) continue;
    if (text[index] === '[') brackets.push(index);
    else if (text[index] === ']' && brackets.length) {
      const opening = brackets.pop();
      if (text[index + 1] !== '(') continue;
      const destination = destinationAt(text, index + 2);
      if (destination === undefined) continue;
      const ending = inlineLinkEnd(text, destination.end);
      if (ending === undefined) continue;
      links.push({ target: destination.target, line: text.slice(0, opening).split('\n').length });
      index = ending;
    }
  }
  for (const match of text.matchAll(/^ {0,3}\[[^\]\n]+\]:\s*/gm)) {
    const destination = destinationAt(text, match.index + match[0].length);
    if (destination !== undefined) links.push({ target: destination.target, line: text.slice(0, match.index).split('\n').length });
  }
  return links;
}

function anchors(source) {
  const text = withoutFences(source);
  const result = new Set();
  const counts = new Map();
  const headings = [...text.matchAll(/^ {0,3}#{1,6}\s+(.+?)(?:\s+#+)?\s*$/gm)].map(match => match[1]);
  for (const heading of headings) {
    const slug = heading.replace(/<[^>]*>/g, '').toLowerCase()
      .replace(/[^\p{L}\p{N}\s_-]/gu, '').replace(/\s/g, '-');
    const count = counts.get(slug) ?? 0;
    result.add(count ? `${slug}-${count}` : slug);
    counts.set(slug, count + 1);
  }
  for (const match of text.matchAll(/<(?:a|h[1-6])\b[^>]*\b(?:id|name)=["']([^"']+)["'][^>]*>/gi)) result.add(match[1]);
  return result;
}

export async function checkDocumentation(rootDirectory) {
  const root = await fs.realpath(rootDirectory);
  const documents = await markdownFiles(root);
  const failures = [];
  const anchorCache = new Map();
  let checkedLinks = 0;
  for (const document of documents) {
    for (const link of destinations(await fs.readFile(document, 'utf8'))) {
      const target = link.target.replace(/\\([\\`*{}[\]()#+.!<> _-])/g, '$1');
      if (/^(?:[A-Za-z][A-Za-z0-9+.-]*:|\/\/)/.test(target)) continue;
      checkedLinks++;
      const fail = reason => failures.push({ document: path.relative(root, document), ...link, reason });
      let filename;
      let fragment;
      try {
        const hash = target.indexOf('#');
        fragment = hash >= 0 ? decodeURIComponent(target.slice(hash + 1)) : '';
        filename = decodeURIComponent((hash >= 0 ? target.slice(0, hash) : target).split('?')[0]);
      } catch {
        fail('invalid percent encoding');
        continue;
      }
      const destination = filename ? path.resolve(filename.startsWith('/') ? root : path.dirname(document), filename.replace(/^\//, '')) : document;
      try {
        const resolved = await fs.realpath(destination);
        const relative = path.relative(root, resolved);
        if (relative === '..' || relative.startsWith(`..${path.sep}`) || path.isAbsolute(relative)) {
          fail('target leaves this repository');
          continue;
        }
        await fs.access(resolved);
        if (fragment && /\.md$/i.test(resolved)) {
          if (!anchorCache.has(resolved)) anchorCache.set(resolved, anchors(await fs.readFile(resolved, 'utf8')));
          if (!anchorCache.get(resolved).has(fragment)) fail('Markdown heading or explicit anchor not found');
        }
      } catch (error) {
        if (error.code === 'ENOENT' || error.code === 'ENOTDIR') fail('target not found');
        else throw error;
      }
    }
  }
  return { documents: documents.length, checkedLinks, failures };
}

const invokedPath = process.argv[1] && path.resolve(process.argv[1]);
if (invokedPath === fileURLToPath(import.meta.url)) {
  const root = process.argv[2] ?? fileURLToPath(new URL('../', import.meta.url));
  const result = await checkDocumentation(root);
  for (const failure of result.failures) console.error(`${failure.document}:${failure.line}: ${failure.target}: ${failure.reason}`);
  console.log(`Checked ${result.checkedLinks} local links in ${result.documents} Markdown files; ${result.failures.length} failures.`);
  if (result.failures.length) process.exitCode = 1;
}
