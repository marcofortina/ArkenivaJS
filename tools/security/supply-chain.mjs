// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { execFileSync, spawnSync } from 'node:child_process';
import { existsSync, mkdirSync, readFileSync, realpathSync, writeFileSync } from 'node:fs';
import { basename, dirname, isAbsolute, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { parse, parseAllDocuments } from 'yaml';

const root = fileURLToPath(new URL('../../', import.meta.url));
const digest = (bytes) => createHash('sha256').update(bytes).digest('hex');
const git = (...args) => execFileSync('git', args, { cwd: root, encoding: 'utf8' }).trim();

/** Check component identity, declared licenses and a closed local dependency graph. */
export function validateSbom(document, manifest, dependencies = []) {
  assert.equal(document.spdxVersion, 'SPDX-2.3');
  assert.equal(document.dataLicense, 'CC0-1.0');
  assert.equal(document.SPDXID, 'SPDXRef-DOCUMENT');
  assert.ok(Array.isArray(document.packages) && document.packages.length > 0);
  const identifiers = new Set([document.SPDXID]);
  for (const component of document.packages) {
    assert.ok(typeof component.SPDXID === 'string' && !identifiers.has(component.SPDXID));
    identifiers.add(component.SPDXID);
    assert.ok(typeof component.name === 'string' && component.name.length > 0);
    assert.ok(typeof component.versionInfo === 'string' && component.versionInfo.length > 0);
    assert.ok(
      typeof component.licenseDeclared === 'string' &&
        !['', 'NOASSERTION', 'NONE'].includes(component.licenseDeclared),
      'Every SBOM component requires a reviewed declared license: ' + component.name,
    );
  }
  const primary = document.packages.find((item) => item.SPDXID === 'SPDXRef-RootPackage');
  assert.equal(primary?.name, manifest.name);
  assert.equal(primary?.versionInfo, manifest.version);
  assert.equal(primary?.licenseDeclared, manifest.license);
  assert.ok(Array.isArray(document.relationships));
  assert.ok(
    document.relationships.some(
      (item) =>
        item.spdxElementId === document.SPDXID &&
        item.relationshipType === 'DESCRIBES' &&
        item.relatedSpdxElement === primary.SPDXID,
    ),
    'The document must describe its intended root package',
  );
  for (const relationship of document.relationships) {
    assert.ok(identifiers.has(relationship.spdxElementId), 'Unknown relationship source');
    assert.ok(identifiers.has(relationship.relatedSpdxElement), 'Unknown relationship target');
  }
  for (const dependency of dependencies) {
    const component = document.packages.find(
      (item) => item.name === dependency.name && item.versionInfo === dependency.version,
    );
    assert.ok(component, 'The SBOM omitted a locked direct dependency: ' + dependency.name);
    assert.ok(
      document.relationships.some(
        (item) =>
          item.spdxElementId === primary.SPDXID &&
          item.relationshipType === 'DEPENDS_ON' &&
          item.relatedSpdxElement === component.SPDXID,
      ),
      'The SBOM omitted a direct dependency relationship: ' + dependency.name,
    );
  }
  return { components: document.packages.length, relationships: document.relationships.length };
}

/** Retain pnpm-native evidence outside Git without modifying source or installing tooling. */
export function createSupplyChainEvidence(destination, allowDirty = false) {
  assert.ok(isAbsolute(destination), 'The evidence destination must be absolute');
  const output = join(realpathSync(dirname(destination)), basename(destination));
  for (let parent = dirname(output); ; parent = dirname(parent)) {
    assert.ok(!existsSync(join(parent, '.git')), 'Supply-chain evidence must stay outside Git');
    if (parent === dirname(parent)) break;
  }
  const revision = git('rev-parse', 'HEAD');
  const status = git('status', '--porcelain=v1', '--untracked-files=all');
  assert.ok(allowDirty || !status, 'Release evidence requires a clean source checkout');
  const inputs = new Map();
  const read = (path) => {
    const bytes = readFileSync(join(root, path));
    inputs.set(path, digest(bytes));
    return bytes.toString();
  };
  const packageManifest = JSON.parse(read('package.json'));
  const version = execFileSync('pnpm', ['--version'], { cwd: root, encoding: 'utf8' }).trim();
  assert.equal(packageManifest.packageManager, 'pnpm@' + version);
  const lockDocuments = parseAllDocuments(read('pnpm-lock.yaml')).map((document) => {
    assert.equal(document.errors.length, 0, 'The lockfile must parse without errors');
    return document.toJS();
  });
  const workspaceLocks = lockDocuments.filter(
    (document) => document.settings && document.importers,
  );
  assert.equal(workspaceLocks.length, 1);
  const lock = workspaceLocks[0];
  const projects = Object.entries(lock.importers).map(([directory, importer]) => {
    assert.ok(!isAbsolute(directory) && !directory.split('/').includes('..'));
    const path = directory === '.' ? 'package.json' : directory + '/package.json';
    const manifest = JSON.parse(read(path));
    assert.equal(manifest.license, 'AGPL-3.0-or-later', path);
    const dependencies = [];
    for (const scope of ['dependencies', 'devDependencies', 'optionalDependencies']) {
      for (const [name, declared] of Object.entries(manifest[scope] ?? {})) {
        const locked = importer[scope]?.[name];
        assert.equal(locked?.specifier, declared, 'Manifest and lockfile disagree: ' + path);
        assert.ok(typeof locked.version === 'string');
        dependencies.push({ name, scope, declared, locked: locked.version });
      }
    }
    return { directory, manifest, dependencies };
  });
  const manifests = new Map(projects.map((project) => [project.manifest.name, project.manifest]));
  const workspace = parse(read('pnpm-workspace.yaml'));
  const patches = Object.entries(workspace.patchedDependencies ?? {}).map(([dependency, path]) => {
    assert.ok(typeof path === 'string' && !isAbsolute(path) && !path.split('/').includes('..'));
    read(path);
    return { dependency, path, sha256: inputs.get(path) };
  });
  mkdirSync(output, { mode: 0o700 });
  const save = (name, value) =>
    writeFileSync(join(output, name), JSON.stringify(value, null, 2) + '\n', {
      flag: 'wx',
      mode: 0o600,
    });
  let invocation = 0;
  const pnpm = (args) => {
    const result = spawnSync('pnpm', args, {
      cwd: root,
      encoding: 'utf8',
      timeout: 120000,
      maxBuffer: 64 * 1024 * 1024,
    });
    writeFileSync(join(output, 'command-' + ++invocation + '.log'), result.stderr ?? '', {
      flag: 'wx',
      mode: 0o600,
    });
    assert.ok(
      !result.error && result.status === 0,
      'Supply-chain command failed; inspect private logs',
    );
    return JSON.parse(result.stdout);
  };
  const dependenciesFor = (project, runtimeOnly) =>
    project.dependencies
      .filter((dependency) => !runtimeOnly || dependency.scope !== 'devDependencies')
      .map((dependency) => ({
        name: dependency.name,
        version: dependency.locked.startsWith('link:')
          ? manifests.get(dependency.name)?.version
          : dependency.locked.split('(')[0],
      }));
  const checkWorkspaceEdges = (document, runtimeOnly) => {
    for (const project of projects) {
      const component = document.packages.find((item) => item.name === project.manifest.name);
      if (!component) continue;
      for (const dependency of dependenciesFor(
        project,
        runtimeOnly || project.manifest.name !== document.name,
      )) {
        const target = document.packages.find(
          (item) => item.name === dependency.name && item.versionInfo === dependency.version,
        );
        assert.ok(target, 'The SBOM omitted a workspace dependency: ' + dependency.name);
        assert.ok(
          document.relationships.some(
            (item) =>
              item.spdxElementId === component.SPDXID &&
              item.relationshipType === 'DEPENDS_ON' &&
              item.relatedSpdxElement === target.SPDXID,
          ),
          'The SBOM omitted a workspace dependency edge: ' +
            project.manifest.name +
            ' -> ' +
            dependency.name,
        );
      }
    }
  };
  const workspaceSboms = [];
  const components = new Set();
  for (const project of projects) {
    const document = pnpm(['--filter', project.manifest.name, 'sbom', '--sbom-format', 'spdx']);
    const counts = validateSbom(document, project.manifest, dependenciesFor(project, false));
    checkWorkspaceEdges(document, false);
    const filename =
      (project.directory === '.' ? 'workspace-root' : project.directory.replaceAll('/', '-')) +
      '.full.spdx.json';
    save(filename, document);
    workspaceSboms.push({ name: project.manifest.name, file: filename, ...counts });
    for (const component of document.packages)
      components.add(component.name + '@' + component.versionInfo);
  }
  const packages = [];
  for (const project of projects.filter((item) => item.directory.startsWith('packages/'))) {
    const runtime = dependenciesFor(project, true);
    const document = pnpm([
      '--filter',
      project.manifest.name,
      'sbom',
      '--sbom-format',
      'spdx',
      '--prod',
    ]);
    const counts = validateSbom(document, project.manifest, runtime);
    checkWorkspaceEdges(document, true);
    const filename = basename(project.directory) + '.runtime.spdx.json';
    save(filename, document);
    packages.push({ name: project.manifest.name, file: filename, ...counts });
  }
  const licenses = pnpm(['licenses', 'list', '--json']);
  save(
    'licenses.json',
    Object.entries(licenses).flatMap(([license, components]) =>
      components.map((component) => ({
        name: component.name,
        versions: component.versions,
        license,
      })),
    ),
  );
  const inventory = {
    formatVersion: 1,
    revision,
    dirty: Boolean(status),
    runtime: { node: process.version, platform: process.platform, architecture: process.arch },
    packageManager: packageManifest.packageManager,
    projects: projects.map(({ directory, manifest, dependencies }) => ({
      directory,
      name: manifest.name,
      version: manifest.version,
      license: manifest.license,
      dependencies,
    })),
    lockedPackages: lockDocuments.flatMap((document, section) =>
      Object.entries(document.packages ?? {}).map(([identity, value]) => ({
        section,
        identity,
        resolution: value.resolution,
        engines: value.engines ?? null,
        os: value.os ?? null,
        cpu: value.cpu ?? null,
      })),
    ),
    patches,
    inputs: Object.fromEntries(inputs),
    workspaceSboms,
    uniqueComponents: components.size,
    runtimeSboms: packages,
  };
  for (const [path, expected] of inputs)
    assert.equal(
      digest(readFileSync(join(root, path))),
      expected,
      'Source changed during inventory',
    );
  assert.equal(git('rev-parse', 'HEAD'), revision);
  assert.equal(git('status', '--porcelain=v1', '--untracked-files=all'), status);
  save('inventory.json', inventory);
  console.log(
    'Supply-chain evidence retained: ' +
      projects.length +
      ' workspace projects, ' +
      packages.length +
      ' runtime SBOMs, ' +
      components.size +
      ' workspace components.',
  );
  return inventory;
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const args = process.argv.slice(2);
  assert.ok(
    args.length === 1 || (args.length === 2 && args[1] === '--allow-dirty'),
    'Use supply-chain.mjs ABSOLUTE_OUTPUT [--allow-dirty]',
  );
  createSupplyChainEvidence(args[0], args[1] === '--allow-dirty');
}
