// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import assert from 'node:assert/strict';
import { mkdtemp, mkdir, writeFile, rm, symlink } from 'node:fs/promises';
import { createRequire } from 'node:module';
import { tmpdir } from 'node:os';
import { dirname, join, resolve, relative } from 'node:path';
import { test } from 'node:test';
import { pathToFileURL } from 'node:url';

const require = createRequire(import.meta.url);
const eslintRequire = createRequire(require.resolve('eslint/package.json'));
const typedocRequire = createRequire(require.resolve('typedoc/package.json'));
const parserRequire = createRequire(
  createRequire(require.resolve('typescript-eslint/package.json')).resolve(
    '@typescript-eslint/parser',
  ),
);
const estreeRequire = createRequire(parserRequire.resolve('@typescript-eslint/typescript-estree'));
const configArrayRequire = createRequire(eslintRequire.resolve('@eslint/config-array'));
const graphqlRequire = createRequire(resolve('packages/graphql/package.json'));
const graphqlConfigRequire = createRequire(graphqlRequire.resolve('graphql-config'));
const parents = [
  eslintRequire,
  configArrayRequire,
  estreeRequire,
  graphqlConfigRequire,
  typedocRequire,
];

async function ownedFiles(action) {
  const directory = await mkdtemp(join(tmpdir(), 'mmc-'));
  try {
    const files = {
      'src/main.ts': 'export const main: number = 1;\n',
      'src/main.js': 'export const main = 1;\n',
      'src/nested/child.ts': 'export const child: number = 2;\n',
      'src/nested/note.md': '# Child\n',
      'src/.hidden/secret.ts': 'export const hidden: number = 3;\n',
      'src/node_modules/vendor.ts': 'export const vendor: number = 4;\n',
      'other/away.ts': 'export const away: number = 5;\n',
      'README.md': '# Owned fixture\n',
    };
    for (const [name, content] of Object.entries(files)) {
      const path = join(directory, name);
      await mkdir(dirname(path), { recursive: true, mode: 0o700 });
      await writeFile(path, content, { flag: 'wx', mode: 0o600 });
    }
    return await action(directory);
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
}

test('All five development parents resolve official minimatch 11 and retain their matching APIs', () => {
  for (const parent of parents) {
    assert.equal(parent('minimatch/package.json').version, '11.0.5');
    const { Minimatch, minimatch } = parent('minimatch');
    const matcher = new Minimatch('src/**/*.{js,ts}', { dot: true });
    assert.equal(matcher.pattern, 'src/**/*.{js,ts}');
    assert.equal(matcher.match('src/nested/child.ts'), true);
    assert.equal(matcher.match('src/.hidden/secret.ts'), true);
    assert.equal(matcher.match('other/away.ts'), false);
    assert.equal(matcher.match('src/nested', true), true);
    assert.equal(minimatch('src/nested/note.md', 'src/**/*.ts', { dot: true }), false);
    assert.equal(minimatch('src/.hidden/secret.ts', 'src/**/*.ts', { dot: false }), false);
  }
});

test('TypeDoc partial recursion preserves the bounded minimatch 10 row-hit oracle', () => {
  const { Minimatch } = typedocRequire('minimatch');
  // Expected values describe TypeDoc's original positive row loop, not full negation.
  const cases = [
    ['src/**/*.ts', ['src'], true],
    ['src/**/*.ts', ['src', 'nested'], true],
    ['src/**/*.ts', ['other'], false],
    ['src/**/*.ts', ['src', '.hidden'], false],
    ['{src,other}/**/*.ts', ['other', 'nested'], true],
    ['src/@(nested|extra)/*.ts', ['src', 'nested'], true],
    ['src/@(nested|extra)/*.ts', ['src', 'elsewhere'], false],
    ['src/**/nested/**/child.ts', ['src', 'a', 'nested', 'b'], true],
    ['!src/**/*.ts', ['src', 'nested'], true],
    ['!src/**/*.ts', ['other'], false],
    ['!!src/**/*.ts', ['src', 'nested'], true],
    ['#src/**/*.ts', ['src'], false],
    ['', ['src'], false],
    ['/owned/src/**/*.ts', ['', 'owned', 'src', 'nested'], true],
    ['/owned/src/**/*.ts', ['', 'foreign', 'src'], false],
    ['C:/owned/src/**/*.ts', ['C:', 'owned', 'src', 'nested'], true],
    ['C:/owned/src/**/*.ts', ['D:', 'owned', 'src'], false],
    ['src/nested/', ['src', 'nested'], true],
    ['src/nested/', ['src', 'other'], false],
    ['src/\\[literal\\]/*.ts', ['src', '[literal]'], true],
    ['src/\\[literal\\]/*.ts', ['src', 'literal'], false],
  ];
  for (const [pattern, parts, expected] of cases) {
    const recurse = new Minimatch(pattern, { flipNegate: true });
    assert.equal(recurse.match(parts.join('/'), true), expected, `${pattern}: ${parts.join('/')}`);
  }
  const full = new Minimatch('!src/**/*.ts');
  assert.equal(full.match('src/nested/child.ts'), false);
  assert.equal(full.match('other/away.ts'), true);
});

test('Published TypeDoc glob discovers nested and brace entries while preserving exclusions and symlink policy', async () => {
  const root = dirname(typedocRequire.resolve('typedoc/package.json'));
  // Exercise the published exported utility; the complete docs command covers the CLI.
  const { glob, createGlobString, deriveRootDir } = await import(
    pathToFileURL(join(root, 'dist/node-utils.js')).href
  );
  await ownedFiles(async (directory) => {
    const names = (result) => result.map((path) => relative(directory, path)).sort();
    assert.deepEqual(names(glob(join(directory, 'src/**/*.ts'), directory)), [
      'src/main.ts',
      'src/nested/child.ts',
    ]);
    assert.deepEqual(names(glob(join(directory, '{src,other}/**/*.ts'), directory)), [
      'other/away.ts',
      'src/main.ts',
      'src/nested/child.ts',
    ]);
    assert.deepEqual(names(glob(join(directory, 'src/node_modules/**/*.ts'), directory)), [
      'src/node_modules/vendor.ts',
    ]);
    assert.deepEqual(names(glob(join(directory, 'src/@(nested|missing)/*.ts'), directory)), [
      'src/nested/child.ts',
    ]);
    assert.deepEqual(names(glob('!' + join(directory, 'src/**/*.ts'), directory)), [
      'README.md',
      'src/main.js',
      'src/nested/note.md',
    ]);
    assert.deepEqual(glob('#' + join(directory, 'src/**/*.ts'), directory), []);
    assert.deepEqual(glob('', directory), []);
    assert.deepEqual(
      names(glob(join(directory, 'src/nested'), directory, { includeDirectories: true })),
      ['src/nested'],
    );
    assert.equal(createGlobString(directory, 'src/**/*.ts'), join(directory, 'src/**/*.ts'));
    assert.equal(deriveRootDir([join(directory, 'src/**/*.ts')]), directory);
    await symlink(join(directory, 'src/nested'), join(directory, 'alias'), 'dir');
    assert.deepEqual(glob(join(directory, 'alias/**/*.ts'), directory), []);
    assert.deepEqual(
      names(glob(join(directory, 'alias/**/*.ts'), directory, { followSymlinks: true })),
      ['alias/child.ts'],
    );
  });
});

test('Actual ESLint and config-array consumers retain included and excluded file decisions', async () => {
  const { ESLint } = require('eslint');
  const { ConfigArray } = eslintRequire('@eslint/config-array');
  await ownedFiles(async (directory) => {
    const configs = new ConfigArray([{ ignores: ['src/nested/**'] }, { files: ['src/**/*.js'] }], {
      basePath: directory,
    });
    await configs.normalize();
    assert.equal(configs.getConfigStatus(join(directory, 'src/main.js')), 'matched');
    assert.equal(configs.getConfigStatus(join(directory, 'src/nested/child.js')), 'ignored');
    assert.equal(configs.getConfigStatus(join(directory, 'other/away.ts')), 'unconfigured');
    const eslint = new ESLint({
      cwd: directory,
      overrideConfigFile: true,
      overrideConfig: [
        { ignores: ['src/nested/**'] },
        { files: ['src/**/*.js'], languageOptions: { ecmaVersion: 'latest' } },
      ],
    });
    const results = await eslint.lintFiles(['src/**/*.js']);
    assert.equal(results.length, 1);
    assert.equal(relative(directory, results[0].filePath), 'src/main.js');
    assert.equal(results[0].errorCount, 0);
    assert.equal(await eslint.isPathIgnored(join(directory, 'src/nested/child.js')), true);
  });
});

test('Actual TypeScript project service accepts only the allowed default-project glob', async () => {
  const { parser } = require('typescript-eslint');
  await ownedFiles(async (directory) => {
    const source = 'const value: number = 1; export { value };';
    await writeFile(
      join(directory, 'tsconfig.json'),
      JSON.stringify({
        compilerOptions: { strict: true, noEmit: true },
        include: ['inside.ts'],
      }),
      { flag: 'wx', mode: 0o600 },
    );
    for (const file of ['inside.ts', 'allowed.ts', 'denied.ts'])
      await writeFile(join(directory, file), source, { flag: 'wx', mode: 0o600 });
    const options = {
      tsconfigRootDir: directory,
      projectService: { defaultProject: 'tsconfig.json', allowDefaultProject: ['allowed.ts'] },
      ecmaVersion: 'latest',
      sourceType: 'module',
    };
    const accepted = parser.parseForESLint(source, {
      ...options,
      filePath: join(directory, 'allowed.ts'),
    });
    assert.ok(accepted.ast && accepted.services.program);
    assert.throws(
      () =>
        parser.parseForESLint(source, {
          ...options,
          filePath: join(directory, 'denied.ts'),
        }),
      /allowDefaultProject/,
    );
  });
});

test('Actual GraphQLConfig public loading keeps local document and project include/exclude boundaries', async () => {
  const { loadConfig } = graphqlRequire('graphql-config');
  await ownedFiles(async (directory) => {
    const source = 'query Owned { ping }\n';
    await mkdir(join(directory, 'documents/ignored'), { recursive: true, mode: 0o700 });
    await mkdir(join(directory, 'include/private'), { recursive: true, mode: 0o700 });
    for (const [file, data] of [
      ['schema.graphql', 'type Query { ping: String! }\n'],
      ['documents/query.graphql', source],
      ['documents/ignored/query.graphql', source],
      ['include/public.graphql', source],
      ['include/private/query.graphql', source],
    ])
      await writeFile(join(directory, file), data, { flag: 'wx', mode: 0o600 });
    const filepath = join(directory, 'graphql.config.json');
    await writeFile(
      filepath,
      JSON.stringify({
        projects: {
          owned: {
            schema: 'schema.graphql',
            documents: 'documents/**/*.graphql',
            include: ['include/**/*.graphql'],
            exclude: ['include/private/**', 'documents/ignored/**'],
          },
        },
      }),
      { flag: 'wx', mode: 0o600 },
    );
    const config = await loadConfig({ filepath, rootDir: directory, legacy: false });
    const project = config.getProject('owned');
    assert.equal(project.match(join(directory, 'include/public.graphql')), true);
    assert.equal(project.match(join(directory, 'include/private/query.graphql')), false);
    assert.equal(project.match(join(directory, 'other/away.ts')), false);
    assert.equal(config.getProjectForFile(join(directory, 'include/public.graphql')).name, 'owned');
    assert.throws(
      () => config.getProjectForFile(join(directory, 'other/away.ts')),
      /doesn't match any project/,
    );
    assert.equal(
      (await project.getSchema()).getQueryType().getFields().ping.type.toString(),
      'String!',
    );
    const documents = await project.getDocuments();
    assert.equal(documents.length, 1);
    assert.equal(documents[0].document.definitions[0].name.value, 'Owned');
  });
});
