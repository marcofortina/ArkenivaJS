// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { createRequire } from 'node:module';
import { fileURLToPath } from 'node:url';
import { mkdir, readFile, readdir, writeFile, rm } from 'node:fs/promises';
import { join, dirname, resolve, parse } from 'node:path';
import { createHash } from 'node:crypto';
import { build, stop } from 'esbuild-wasm';

const root = fileURLToPath(new URL('../', import.meta.url));
const require = createRequire(new URL('../package.json', import.meta.url));
const graphiql = createRequire(require.resolve('graphiql/package.json'));
const react = createRequire(graphiql.resolve('@graphiql/react/package.json'));
const destination = join(root, 'dist/ide');
await rm(destination, { recursive: true, force: true });
await mkdir(destination, { recursive: true });
try {
  const result = await build({
    absWorkingDir: root,
    entryPoints: {
      app: 'browser/ide.ts',
      'worker-editor': react.resolve('monaco-editor/esm/vs/editor/editor.worker.js'),
      'worker-json': react.resolve('monaco-editor/esm/vs/language/json/json.worker.js'),
      'worker-graphql': react.resolve('monaco-graphql/esm/graphql.worker.js'),
    },
    bundle: true,
    splitting: true,
    format: 'esm',
    platform: 'browser',
    target: 'es2022',
    outdir: join(destination, 'assets'),
    entryNames: '[name]',
    chunkNames: 'chunk-[hash]',
    assetNames: 'asset-[hash]',
    minify: true,
    sourcemap: false,
    legalComments: 'linked',
    banner: {
      js: '/* SPDX-License-Identifier: AGPL-3.0-or-later\nCopyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>\nThird-party notices are retained in linked legal files and the licenses directory. */',
    },
    define: { 'process.env.NODE_ENV': '"production"' },
    loader: { '.ttf': 'file', '.svg': 'dataurl' },
    metafile: true,
  });
  for (const output of Object.values(result.metafile.outputs))
    for (const dependency of output.imports)
      if (dependency.external && !dependency.path.startsWith('data:'))
        throw new Error('GraphQL IDE assets must not load external modules');
  const vendors = new Map();
  for (const input of Object.keys(result.metafile.inputs)) {
    let directory = dirname(resolve(root, input));
    while (directory !== parse(directory).root) {
      let metadata;
      try {
        metadata = JSON.parse(await readFile(join(directory, 'package.json'), 'utf8'));
      } catch (error) {
        if (error.code !== 'ENOENT') throw error;
      }
      if (metadata?.name && metadata.version) {
        if (metadata.name !== '@arkenivajs/graphql')
          vendors.set(`${metadata.name}@${metadata.version}`, directory);
        break;
      }
      directory = dirname(directory);
    }
  }
  const notices = [];
  const missing = [];
  const reviewedNotices = new Map([
    [
      '@graphiql/plugin-doc-explorer@0.4.4',
      ['graphiql.LICENSE', '35a11da7e877009ddc57405844209908cfc567adda0ec1daf410368c9f5b0d01'],
    ],
    [
      '@graphiql/plugin-history@0.4.4',
      ['graphiql.LICENSE', '35a11da7e877009ddc57405844209908cfc567adda0ec1daf410368c9f5b0d01'],
    ],
    [
      'react-compiler-runtime@1.0.0',
      ['react.LICENSE', 'da6d3703ed11cbe42bd212c725957c98da23cbff1998c05fa4b3d976d1a58e93'],
    ],
    [
      'react-remove-scroll-bar@2.3.8',
      [
        'react-remove-scroll-bar.LICENSE',
        'a79aae0c0f21990d9d963bb3c5a79cdcea9a46f8523ba55c58d7fe776b6ebc84',
      ],
    ],
  ]);
  for (const [id, directory] of [...vendors].sort(([a], [b]) => a.localeCompare(b))) {
    const names = (await readdir(directory, { withFileTypes: true }))
      .filter(
        (entry) =>
          entry.isFile() &&
          /^(?:licen[cs]e|notice|copying|third[-_]?party[-_]?notices?)(?:[._-].*)?$/i.test(
            entry.name,
          ),
      )
      .map((entry) => entry.name);
    const target = join(destination, 'licenses', id.replaceAll('/', '_'));
    await mkdir(target, { recursive: true });
    if (!names.length) {
      const reviewed = reviewedNotices.get(id);
      if (!reviewed) {
        missing.push(id);
        continue;
      }
      const text = await readFile(join(root, 'compat/licenses', reviewed[0]));
      if (createHash('sha256').update(text).digest('hex') !== reviewed[1])
        throw new Error('A reviewed dependency notice has changed');
      await writeFile(join(target, 'LICENSE'), text);
    }
    for (const name of names)
      await writeFile(join(target, name), await readFile(join(directory, name)));
    notices.push(id);
  }
  if (missing.length)
    throw new Error(
      `Bundled GraphQL IDE dependencies require their upstream notices: ${missing.join(', ')}`,
    );
  await writeFile(
    join(destination, 'THIRD_PARTY_NOTICES.txt'),
    'Bundled dependency notices are preserved verbatim in licenses/.\n\n' +
      notices.join('\n') +
      '\n',
  );
  const files = [];
  for (const name of (await readdir(join(destination, 'assets'))).sort()) {
    const content = await readFile(join(destination, 'assets', name));
    files.push({
      name,
      bytes: content.byteLength,
      sha256: createHash('sha256').update(content).digest('hex'),
    });
  }
  await writeFile(join(destination, 'manifest.json'), JSON.stringify({ format: 1, files }) + '\n');
} finally {
  stop();
}
