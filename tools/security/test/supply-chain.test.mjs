// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import assert from 'node:assert/strict';
import { test } from 'node:test';
import { mkdtempSync, rmSync, symlinkSync, existsSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { createSupplyChainEvidence, validateSbom } from '../supply-chain.mjs';

const manifest = { name: '@arkenivajs/example', version: '0.1.0', license: 'AGPL-3.0-or-later' };
const document = () => ({
  spdxVersion: 'SPDX-2.3',
  dataLicense: 'CC0-1.0',
  SPDXID: 'SPDXRef-DOCUMENT',
  packages: [
    {
      SPDXID: 'SPDXRef-RootPackage',
      name: manifest.name,
      versionInfo: manifest.version,
      licenseDeclared: manifest.license,
    },
    { SPDXID: 'SPDXRef-fastify', name: 'fastify', versionInfo: '5.12.7', licenseDeclared: 'MIT' },
  ],
  relationships: [
    {
      spdxElementId: 'SPDXRef-DOCUMENT',
      relatedSpdxElement: 'SPDXRef-RootPackage',
      relationshipType: 'DESCRIBES',
    },
    {
      spdxElementId: 'SPDXRef-RootPackage',
      relatedSpdxElement: 'SPDXRef-fastify',
      relationshipType: 'DEPENDS_ON',
    },
  ],
});
const dependencies = [{ name: 'fastify', version: '5.12.7' }];

test('Supply-chain checks reject missing, mismatched and disconnected locked dependencies', () => {
  validateSbom(document(), manifest, dependencies);
  const missing = document();
  missing.packages.pop();
  missing.relationships.pop();
  assert.throws(
    () => validateSbom(missing, manifest, dependencies),
    /omitted a locked direct dependency/,
  );
  const disconnected = document();
  disconnected.relationships.pop();
  assert.throws(
    () => validateSbom(disconnected, manifest, dependencies),
    /omitted a direct dependency relationship/,
  );
  const mismatched = document();
  mismatched.packages[1].versionInfo = '5.0.0';
  assert.throws(
    () => validateSbom(mismatched, manifest, dependencies),
    /omitted a locked direct dependency/,
  );
});

test('Supply-chain checks reject duplicate identifiers, dangling edges and unknown licenses', () => {
  const duplicate = document();
  duplicate.packages.push({ ...duplicate.packages[1] });
  assert.throws(() => validateSbom(duplicate, manifest, dependencies));
  const dangling = document();
  dangling.relationships[1].relatedSpdxElement = 'SPDXRef-missing';
  assert.throws(
    () => validateSbom(dangling, manifest, dependencies),
    /Unknown relationship target/,
  );
  const unknown = document();
  unknown.packages[1].licenseDeclared = 'NOASSERTION';
  assert.throws(() => validateSbom(unknown, manifest, dependencies), /reviewed declared license/);
  const root = document();
  root.packages[0].versionInfo = '9.0.0';
  assert.throws(() => validateSbom(root, manifest, dependencies));
});

test('Evidence destinations reject Git paths, relative paths and symlink paths into the checkout', () => {
  assert.throws(() => createSupplyChainEvidence('relative-evidence'), /must be absolute/);
  const root = fileURLToPath(new URL('../../../', import.meta.url));
  const target = join(root, '.supply-chain-fixture');
  assert.throws(() => createSupplyChainEvidence(target, true), /must stay outside Git/);
  assert.equal(existsSync(target), false);
  const directory = mkdtempSync(join(tmpdir(), 'arkenivajs-inventory-'));
  try {
    symlinkSync(root, join(directory, 'checkout'), 'dir');
    assert.throws(
      () => createSupplyChainEvidence(join(directory, 'checkout', '.supply-chain-fixture'), true),
      /must stay outside Git/,
    );
    assert.equal(existsSync(target), false);
  } finally {
    rmSync(directory, { recursive: true, force: true });
  }
});
