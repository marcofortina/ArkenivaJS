// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, writeFile, rm, lstat, readFile, symlink } from 'node:fs/promises';
import { tmpdir, networkInterfaces } from 'node:os';
import { join } from 'node:path';
import { KitError } from '@arkenivajs/core';
import { Runtime } from '../../dist/runtime.js';
import { capture } from '../../dist/settings.js';
import { Xsd } from '../../dist/xsd.js';
import { service } from '../../dist/service.js';

if (
  process.env.ARKENIVA_XML_NS_ACTIVE !== '1' ||
  process.getuid?.() === 0 ||
  Object.keys(networkInterfaces()).some((name) => name !== 'lo')
)
  throw new Error(
    'Native XSD tests require the owned isolated network fixture and a non-root user',
  );
const namespace = 'http://www.w3.org/2001/XMLSchema';
const code = (name: string) => (error: unknown) => error instanceof KitError && error.code === name;
const single =
  '<xs:schema xmlns:xs="' +
  namespace +
  '"><xs:element name="amount" type="xs:decimal"/></xs:schema>';

async function runningValidator(directory: string, finished: () => boolean): Promise<number> {
  for (let attempt = 0; attempt < 2000 && !finished(); attempt++) {
    const children = (await readFile('/proc/self/task/' + process.pid + '/children', 'utf8'))
      .trim()
      .split(/\s+/)
      .filter(Boolean);
    for (const value of children) {
      try {
        const command = await readFile('/proc/' + value + '/cmdline', 'utf8');
        if (command.includes('/usr/bin/xmllint') && command.includes(directory + '/'))
          return Number(value);
      } catch (error) {
        if (
          !error ||
          typeof error !== 'object' ||
          !('code' in error) ||
          !['ENOENT', 'ESRCH'].includes(String(error.code))
        )
          throw error;
      }
    }
    await new Promise((resolve) => setTimeout(resolve, 1));
  }
  throw new Error('The owned native validator process was not observed');
}
async function fixture(
  files: Readonly<Record<string, string>> = { invoice: single },
  custom?: (directory: string) => Promise<void>,
) {
  const directory = await mkdtemp(join(tmpdir(), 'arkenivajs-xml-native-'));
  for (const [id, text] of Object.entries(files))
    await writeFile(join(directory, id + '.xsd'), text, { mode: 0o600 });
  let runtime: Runtime | undefined, xsd: Xsd | undefined;
  try {
    await custom?.(directory);
    runtime = new Runtime(
      capture({
        defaults: { maxBytes: 1024 * 1024 },
        policy: {
          maxConcurrent: 2,
          timeoutMs: 5000,
          maxInputBytes: 1024 * 1024,
          maxOutputBytes: 2 * 1024 * 1024,
        },
        xsdSchemaFiles: Object.fromEntries(
          Object.keys(files).map((id) => [id, join(directory, id + '.xsd')]),
        ),
      }),
      new AbortController().signal,
      () => true,
    );
    xsd = await Xsd.create(runtime);
    assert.ok(xsd, 'The vetted real XSD backend must be available');
    const owner = runtime,
      adapter = xsd;
    return {
      directory,
      runtime: owner,
      xsd: adapter,
      xml: service(owner, adapter),
      async close() {
        await owner.close();
        await adapter.close();
        await rm(directory, { recursive: true, force: true });
      },
    };
  } catch (error) {
    await runtime?.close();
    await xsd?.close();
    await rm(directory, { recursive: true, force: true });
    throw error;
  }
}
test('The real libxml2 validator distinguishes schema validity from mere XML well-formedness', async () => {
  const f = await fixture();
  try {
    assert.equal(
      (await f.xml.validateXsd(Buffer.from('<amount>12.50</amount>'), 'invoice')).valid,
      true,
    );
    const invalid = await f.xml.validateXsd(
      Buffer.from('<amount>private-invalid-decimal</amount>'),
      'invoice',
    );
    assert.equal(invalid.valid, false);
    assert.equal(invalid.messages[0]?.code, 'EK_XML_SCHEMA');
    assert.equal(JSON.stringify(invalid).includes('private-invalid-decimal'), false);
    await assert.rejects(
      f.xml.validateXsd(Buffer.from('<amount>'), 'invoice'),
      code('EK_XML_PARSE'),
    );
    await assert.rejects(
      f.xml.validateXsd(Buffer.from('<amount>1</amount>'), 'unknown'),
      code('EK_XML_SCHEMA'),
    );
  } finally {
    await f.close();
  }
});
test('Native XSD includes resolve only registered offline assets and preserve immutable private snapshots', async () => {
  const files = {
    invoice:
      '<xs:schema xmlns:xs="' +
      namespace +
      '"><xs:include schemaLocation="types.xsd"/><xs:element name="amount" type="AmountType"/></xs:schema>',
    types:
      '<xs:schema xmlns:xs="' +
      namespace +
      '"><xs:simpleType name="AmountType"><xs:restriction base="xs:decimal"/></xs:simpleType></xs:schema>',
  };
  const f = await fixture(files),
    snapshot = f.xsd.directory;
  try {
    assert.equal((await lstat(snapshot)).mode & 0o077, 0);
    await writeFile(
      join(f.directory, 'types.xsd'),
      '<xs:schema xmlns:xs="' +
        namespace +
        '"><xs:simpleType name="AmountType"><xs:restriction base="xs:string"/></xs:simpleType></xs:schema>',
    );
    assert.equal(
      (await f.xml.validateXsd(Buffer.from('<amount>invalid</amount>'), 'invoice')).valid,
      false,
    );
    assert.equal(
      (await f.xml.validateXsd(Buffer.from('<amount>4</amount>'), 'invoice')).valid,
      true,
    );
  } finally {
    await f.close();
  }
  await assert.rejects(
    lstat(snapshot),
    (error: unknown) =>
      !!error && typeof error === 'object' && 'code' in error && error.code === 'ENOENT',
  );
});
test('External, unregistered and cyclic native schema imports are rejected before compilation', async () => {
  for (const location of [
    'http://127.0.0.1:1/never.xsd',
    'file:///etc/passwd',
    '../unregistered.xsd',
    'missing.xsd',
  ]) {
    await assert.rejects(
      fixture({
        invoice:
          '<xs:schema xmlns:xs="' +
          namespace +
          '"><xs:include schemaLocation="' +
          location +
          '"/></xs:schema>',
      }),
      code('EK_XML_SECURITY'),
    );
  }
  await assert.rejects(
    fixture({
      invoice:
        '<xs:schema xmlns:xs="' +
        namespace +
        '" xml:base="file:///etc/"><xs:include schemaLocation="types.xsd"/></xs:schema>',
      types: '<xs:schema xmlns:xs="' + namespace + '"/>',
    }),
    code('EK_XML_SECURITY'),
  );
  await assert.rejects(
    fixture({
      invoice:
        '<xs:schema xmlns:xs="' +
        namespace +
        '"><xs:include schemaLocation="types.xsd"/></xs:schema>',
      types:
        '<xs:schema xmlns:xs="' +
        namespace +
        '"><xs:include schemaLocation="invoice.xsd"/></xs:schema>',
    }),
    code('EK_XML_SECURITY'),
  );
});
test('Schema compiler errors, DTDs and filesystem indirection cannot create a false validation capability', async () => {
  await assert.rejects(
    fixture({
      invoice:
        '<xs:schema xmlns:xs="' +
        namespace +
        '"><xs:element name="amount" type="xs:doesNotExist"/></xs:schema>',
    }),
    code('EK_XML_SCHEMA'),
  );
  await assert.rejects(
    fixture({
      invoice:
        '<!DOCTYPE xs:schema SYSTEM "http://127.0.0.1:1/never"><xs:schema xmlns:xs="' +
        namespace +
        '"/>',
    }),
    code('EK_XML_SECURITY'),
  );
  await assert.rejects(
    fixture({ invoice: single }, async (directory) => {
      await writeFile(join(directory, 'target.xsd'), single, { mode: 0o600 });
      await rm(join(directory, 'invoice.xsd'));
      await symlink(join(directory, 'target.xsd'), join(directory, 'invoice.xsd'));
    }),
    code('EK_XML_SECURITY'),
  );
});
test('Unavailable schema storage and canceled validation cannot bypass native XSD controls', async () => {
  const f = await fixture(),
    controller = new AbortController();
  controller.abort();
  try {
    await assert.rejects(
      f.xml.validateXsd(Buffer.from('<amount>1</amount>'), 'invoice', {
        signal: controller.signal,
      }),
      code('EK_ABORTED'),
    );
    await assert.rejects(
      f.xml.validateXsd(Buffer.from('<amount>1</amount>'), 'invoice', { timeoutMs: 1 }),
      code('EK_TIMEOUT'),
    );
    for (let i = 0; f.runtime.active.size && i < 100; i++)
      await new Promise((resolve) => setTimeout(resolve, 5));
    const path = f.xsd.schemas.get('invoice')!;
    assert.ok(path.startsWith(f.xsd.directory + '/'));
    await rm(path);
    await assert.rejects(
      f.xml.validateXsd(Buffer.from('<amount>1</amount>'), 'invoice'),
      code('EK_XML_SCHEMA'),
    );
  } finally {
    await f.close();
  }
});
test('XSD rejects entity and local-file document attacks before the native schema engine', async () => {
  const f = await fixture();
  try {
    for (const text of [
      '<!DOCTYPE amount [<!ENTITY data SYSTEM "file:///etc/passwd">]><amount>&data;</amount>',
      '<!DOCTYPE amount SYSTEM "http://127.0.0.1:1/never"><amount>1</amount>',
      '<amount xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:noNamespaceSchemaLocation="file:///etc/passwd">1</amount>',
    ])
      await assert.rejects(
        f.xml.validateXsd(Buffer.from(text), 'invoice'),
        code('EK_XML_SECURITY'),
      );
    const maps = await readFile('/proc/self/net/route', 'utf8');
    assert.equal(maps.trim().split('\n').length, 1);
  } finally {
    await f.close();
  }
});

test('Caller cancellation kills the actual owned libxml2 process and retains cleanup until its exit', async () => {
  const bulk =
    '<xs:schema xmlns:xs="' +
    namespace +
    '"><xs:element name="items"><xs:complexType><xs:sequence><xs:element name="item" type="xs:string" maxOccurs="unbounded"/></xs:sequence></xs:complexType></xs:element></xs:schema>';
  const f = await fixture({ invoice: bulk }),
    controller = new AbortController();
  let finished = false,
    pid = 0;
  try {
    const input = Buffer.from(
      '<items>' + ('<item>' + 'x'.repeat(32) + '</item>').repeat(16000) + '</items>',
    );
    const pending = f.xml.validateXsd(input, 'invoice', { signal: controller.signal });
    void pending.catch(() => undefined);
    void pending
      .finally(() => {
        finished = true;
      })
      .catch(() => undefined);
    pid = await runningValidator(f.xsd.directory, () => finished);
    controller.abort();
    await assert.rejects(pending, code('EK_ABORTED'));
    await f.runtime.close();
    assert.equal(f.runtime.active.size, 0);
    assert.throws(
      () => process.kill(pid, 0),
      (error: unknown) =>
        !!error && typeof error === 'object' && 'code' in error && error.code === 'ESRCH',
    );
  } finally {
    controller.abort();
    await f.close();
  }
});

test('An actual native validator process failure cannot return a successful schema decision', async () => {
  const bulk =
    '<xs:schema xmlns:xs="' +
    namespace +
    '"><xs:element name="items"><xs:complexType><xs:sequence><xs:element name="item" type="xs:string" maxOccurs="unbounded"/></xs:sequence></xs:complexType></xs:element></xs:schema>';
  const f = await fixture({ invoice: bulk });
  let finished = false;
  try {
    const pending = f.xml.validateXsd(
      Buffer.from('<items>' + ('<item>' + 'x'.repeat(32) + '</item>').repeat(16000) + '</items>'),
      'invoice',
    );
    void pending.catch(() => undefined);
    void pending
      .finally(() => {
        finished = true;
      })
      .catch(() => undefined);
    const pid = await runningValidator(f.xsd.directory, () => finished);
    process.kill(pid, 'SIGKILL');
    await assert.rejects(pending, code('EK_XML_SCHEMA'));
  } finally {
    await f.close();
  }
});

test('Native validation and parser workers share one finite admission budget without a hidden waiting queue', async () => {
  const bulk =
    '<xs:schema xmlns:xs="' +
    namespace +
    '"><xs:element name="items"><xs:complexType><xs:sequence><xs:element name="item" type="xs:string" maxOccurs="unbounded"/></xs:sequence></xs:complexType></xs:element></xs:schema>';
  const f = await fixture({ invoice: bulk });
  let finished = false;
  try {
    const pending = f.xml.validateXsd(
      Buffer.from('<items>' + ('<item>' + 'x'.repeat(32) + '</item>').repeat(16000) + '</items>'),
      'invoice',
    );
    void pending
      .finally(() => {
        finished = true;
      })
      .catch(() => undefined);
    await runningValidator(f.xsd.directory, () => finished);
    const parser = f.xml.parse('<r/>');
    assert.equal(f.runtime.active.size, 2);
    await assert.rejects(f.xml.parse('<overflow/>'), code('EK_XML_SECURITY'));
    assert.equal((await pending).valid, true);
    assert.ok(await parser);
  } finally {
    await f.close();
  }
});

test("Two native XML instances cannot share schema decisions or remove each other's snapshots", async () => {
  const first = await fixture(),
    second = await fixture({
      invoice:
        '<xs:schema xmlns:xs="' +
        namespace +
        '"><xs:element name="amount" type="xs:string"/></xs:schema>',
    });
  try {
    assert.notEqual(first.xsd.directory, second.xsd.directory);
    const value = Buffer.from('<amount>text</amount>');
    assert.equal((await first.xml.validateXsd(value, 'invoice')).valid, false);
    assert.equal((await second.xml.validateXsd(value, 'invoice')).valid, true);
    await first.close();
    assert.equal((await second.xml.validateXsd(value, 'invoice')).valid, true);
  } finally {
    await first.close();
    await second.close();
  }
});
