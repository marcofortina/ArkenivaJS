import assert from 'node:assert/strict';
import { readFileSync, readdirSync, existsSync } from 'node:fs';
import { resolve, dirname, sep } from 'node:path';

const root = resolve('.');
function markdown(directory) {
  if (!existsSync(directory)) return [];
  return readdirSync(directory, { withFileTypes: true }).flatMap((entry) => {
    if (['node_modules', 'dist', 'dist-test'].includes(entry.name)) return [];
    const path = `${directory}/${entry.name}`;
    return entry.isDirectory() ? markdown(path) : path.endsWith('.md') ? [path] : [];
  });
}
const files = ['README.md', ...markdown('docs'), ...markdown('packages'), ...markdown('examples')];
if (existsSync('CONTRIBUTING.md')) files.push('CONTRIBUTING.md');
for (const file of files) {
  const source = readFileSync(file, 'utf8');
  assert.ok(
    !source.includes('```mermaid'),
    `A pinned Mermaid render check is required for diagrams in ${file}`,
  );
  for (const match of source.matchAll(/\[[^\]]+\]\(([^)]+)\)/g)) {
    const target = match[1].split('#')[0];
    if (!target || /^https?:\/\//.test(target)) continue;
    const path = resolve(dirname(file), decodeURIComponent(target));
    assert.ok(
      path.startsWith(root + sep),
      `Documentation link must remain in the product: ${file}`,
    );
    assert.ok(existsSync(path), `Broken documentation link in ${file}: ${target}`);
  }
}
assert.ok(existsSync('.build/api/index.html'), 'API documentation must render successfully');
console.log(`Documentation rendered and ${files.length} Markdown files passed local link checks`);
