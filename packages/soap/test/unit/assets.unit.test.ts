// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, mkdir, writeFile, rm, symlink, chmod } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { KitError } from '@arkenivajs/core';
import { loadAssets } from '../../dist/assets.js';
import { nativeGraph } from '../../dist/backend.js';
import { NativeParser } from '../../dist/parser.js';
import { contract, response } from '../fixture.js';

const code = (name: string) => (error: unknown) => error instanceof KitError && error.code === name;
const schema = contract
  .match(/<xs:schema[\s\S]*?<\/xs:schema>/)![0]
  .replace('<xs:schema ', '<xs:schema xmlns:xs="http://www.w3.org/2001/XMLSchema" ');
const external = contract.replace(
  /<xs:schema[\s\S]*?<\/xs:schema>/,
  '<xs:schema targetNamespace="urn:arkenivajs:stock"><xs:include schemaLocation="types.xsd"/></xs:schema>',
);
async function fixture(work: (directory: string, entry: string) => Promise<void>) {
  const directory = await mkdtemp(join(tmpdir(), 'arkenivajs-soap-assets-'));
  try {
    const entry = join(directory, 'inventory.wsdl');
    await writeFile(entry, external, { mode: 0o600 });
    await writeFile(join(directory, 'types.xsd'), schema, { mode: 0o600 });
    await work(directory, entry);
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
}
test('Actual native WSDL imports use only immutable captured cache entries after original files are removed', async () => {
  await fixture(async (directory, entry) => {
    const assets = await loadAssets(entry, new AbortController().signal);
    assert.equal(assets.documents.length, 2);
    assert.equal(assets.documents.at(-1)?.path, entry);
    assert.ok(Object.isFrozen(assets) && Object.isFrozen(assets.documents));
    assert.ok(assets.documents.every(Object.isFrozen));
    await rm(join(directory, 'types.xsd'));
    await rm(entry);
    const native = await nativeGraph(assets);
    assert.deepEqual(
      native.xmlToObject(response),
      (await nativeGraph(assets)).xmlToObject(response),
    );
    const parser = await NativeParser.create(
      { source: external, assets, protocol: '1.1', timeoutMs: 10000, maxBytes: 1048576 },
      new AbortController().signal,
    );
    try {
      const result = parser.parse(response) as {
        Body: { ReadStockResponse: { quantity: number } };
      };
      assert.equal(result.Body.ReadStockResponse.quantity, 12);
    } finally {
      await parser.close();
    }
  });
});
test('A cache miss never falls back to an existing local file and reversed dependency order is rejected', async () => {
  await fixture(async (_directory, entry) => {
    const assets = await loadAssets(entry, new AbortController().signal);
    await assert.rejects(
      nativeGraph({ entry, documents: [assets.documents.at(-1)!] }),
      code('EK_SOAP_WSDL'),
    );
    await assert.rejects(
      nativeGraph({ entry, documents: [...assets.documents].reverse() }),
      code('EK_SOAP_WSDL'),
    );
  });
});
test('Remote, absolute, encoded and escaping import references fail before compilation', async () => {
  await fixture(async (_directory, entry) => {
    for (const reference of [
      'https://remote.fixture.invalid/types.xsd',
      'file:///private/types.xsd',
      '/private/types.xsd',
      '../types.xsd',
      '%2e%2e/types.xsd',
      'types.xsd?query',
      'types.xsd#part',
      'other\\types.xsd',
    ]) {
      await writeFile(entry, external.replace('types.xsd', reference));
      await assert.rejects(loadAssets(entry, new AbortController().signal), code('EK_SOAP_WSDL'));
    }
  });
});
test('Canonical relative imports may traverse nested directories while remaining inside the approved root', async () => {
  await fixture(async (directory, entry) => {
    await mkdir(join(directory, 'schemas'));
    await writeFile(
      join(directory, 'schemas', 'group.xsd'),
      '<xs:schema xmlns:xs="http://www.w3.org/2001/XMLSchema" targetNamespace="urn:arkenivajs:stock"><xs:include schemaLocation="../types.xsd"/></xs:schema>',
      { mode: 0o600 },
    );
    await writeFile(entry, external.replace('types.xsd', './schemas/group.xsd'));
    const assets = await loadAssets(entry, new AbortController().signal);
    assert.equal(assets.documents.length, 3);
    assert.ok((await nativeGraph(assets)).describeServices());
  });
});
test('Symlinks, writable files, malformed UTF-8, cycles and already canceled loads are rejected', async () => {
  await fixture(async (directory, entry) => {
    const types = join(directory, 'types.xsd');
    await rm(types);
    await symlink(entry, types);
    await assert.rejects(loadAssets(entry, new AbortController().signal), code('EK_SOAP_WSDL'));
    await rm(types);
    await writeFile(types, schema);
    await chmod(types, 0o666);
    await assert.rejects(loadAssets(entry, new AbortController().signal), code('EK_SOAP_WSDL'));
    await chmod(types, 0o600);
    await writeFile(types, Buffer.from([0xff, 0xfe]));
    await assert.rejects(loadAssets(entry, new AbortController().signal), code('EK_SOAP_WSDL'));
    await writeFile(
      types,
      '<xs:schema xmlns:xs="http://www.w3.org/2001/XMLSchema"><xs:include schemaLocation="inventory.wsdl"/></xs:schema>',
    );
    await assert.rejects(loadAssets(entry, new AbortController().signal), code('EK_SOAP_WSDL'));
    await assert.rejects(loadAssets(entry, AbortSignal.abort()), code('EK_ABORTED'));
  });
});
test('Asset graph count and byte ceilings reject oversized contracts without partial publication', async () => {
  await fixture(async (directory, entry) => {
    const types = join(directory, 'types.xsd');
    await writeFile(types, ' '.repeat(1048577));
    await assert.rejects(loadAssets(entry, new AbortController().signal), code('EK_SOAP_WSDL'));
    for (let i = 0; i < 33; i++) {
      await writeFile(
        join(directory, 'part-' + i + '.xsd'),
        '<xs:schema xmlns:xs="http://www.w3.org/2001/XMLSchema">' +
          (i === 32 ? '' : '<xs:include schemaLocation="part-' + (i + 1) + '.xsd"/>') +
          '</xs:schema>',
        { mode: 0o600 },
      );
    }
    await writeFile(entry, external.replace('types.xsd', 'part-0.xsd'));
    await assert.rejects(loadAssets(entry, new AbortController().signal), code('EK_SOAP_WSDL'));
    for (let i = 0; i < 9; i++) {
      await writeFile(
        join(directory, 'part-' + i + '.xsd'),
        '<xs:schema xmlns:xs="http://www.w3.org/2001/XMLSchema">' +
          (i === 8 ? '' : '<xs:include schemaLocation="part-' + (i + 1) + '.xsd"/>') +
          '<!--' +
          'x'.repeat(950000) +
          '--></xs:schema>',
        { mode: 0o600 },
      );
    }
    await assert.rejects(loadAssets(entry, new AbortController().signal), code('EK_SOAP_WSDL'));
  });
});
