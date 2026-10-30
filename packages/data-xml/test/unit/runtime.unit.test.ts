// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { setTimeout as delay } from 'node:timers/promises';
import { createApplication, KitError } from '@arkenivajs/core';
import { dataXmlPlugin, XML_CAPABILITY } from '../../dist/index.js';
import type { XmlService, DataXmlPluginSettings } from '../../dist/index.js';
import { Runtime, operation } from '../../dist/runtime.js';
import { capture } from '../../dist/settings.js';
import { service } from '../../dist/service.js';

const settings: DataXmlPluginSettings = {
  defaults: {},
  policy: { maxConcurrent: 1, timeoutMs: 2000, maxInputBytes: 4096, maxOutputBytes: 16384 },
};
const code = (name: string) => (error: unknown) => error instanceof KitError && error.code === name;
test('The public XML capability executes actual isolated native parsing and writing through its application lifecycle', async () => {
  const app = await createApplication({
    service: { name: 'xml-fixture', version: '1.0.0', environment: 'test' },
    plugins: [dataXmlPlugin(settings)],
  });
  await app.start();
  const xml = app.resolve<XmlService>(XML_CAPABILITY);
  try {
    const document = await xml.parse('<p:r xmlns:p="urn:test" id="001">Ελληνικά &amp; שלום</p:r>', {
      namespaceMode: 'expanded',
    });
    assert.ok(Object.isFrozen(document.root));
    const output = await xml.stringify(document, { namespaceMode: 'expanded' });
    assert.deepEqual(await xml.parse(output, { namespaceMode: 'expanded' }), document);
  } finally {
    await app.stop();
  }
  await assert.rejects(xml.parse('<r/>'), code('EK_RESOURCE_CLOSED'));
});
test('XML admission has no waiting queue and retains a canceled native worker until actual exit', async () => {
  const runtime = new Runtime(capture(settings), new AbortController().signal, () => true),
    xml = service(runtime),
    controller = new AbortController();
  try {
    const first = xml.parse('<r>held</r>', { signal: controller.signal });
    controller.abort();
    await assert.rejects(first, code('EK_ABORTED'));
    await assert.rejects(xml.parse('<r/>'), code('EK_XML_SECURITY'));
    for (let i = 0; runtime.active.size && i < 100; i++) await delay(5);
    assert.equal(runtime.active.size, 0);
    assert.ok(await xml.parse('<r/>'));
  } finally {
    await runtime.close();
  }
});
test('XML deadlines and application shutdown terminate real workers and await actual cleanup', async () => {
  const runtime = new Runtime(capture(settings), new AbortController().signal, () => true),
    xml = service(runtime);
  await assert.rejects(xml.parse('<r/>', { timeoutMs: 1 }), code('EK_TIMEOUT'));
  await runtime.close();
  assert.equal(runtime.active.size, 0);
  const next = new Runtime(capture(settings), new AbortController().signal, () => true),
    pending = service(next).parse('<r/>');
  const closed = next.close();
  await assert.rejects(pending, code('EK_ABORTED'));
  await closed;
  assert.equal(next.active.size, 0);
});
test('XML rejects forged signals, invalid deadlines, unknown options and shared memory before worker allocation', async () => {
  const runtime = new Runtime(capture(settings), new AbortController().signal, () => true),
    xml = service(runtime);
  try {
    for (const timeoutMs of [0, -1, 0.5, Infinity, NaN, 30001])
      assert.throws(() => operation({ timeoutMs }, 30000), code('EK_CONFIG_INVALID'));
    await assert.rejects(
      xml.parse('<r/>', { signal: { aborted: false } as AbortSignal }),
      code('EK_CONFIG_INVALID'),
    );
    await assert.rejects(xml.parse('<r/>', null as never), code('EK_CONFIG_INVALID'));
    await assert.rejects(xml.parse('<r/>', { unknown: true } as never), code('EK_CONFIG_INVALID'));
    await assert.rejects(
      xml.parse(new Uint8Array(new SharedArrayBuffer(4))),
      code('EK_XML_SECURITY'),
    );
    assert.equal(runtime.active.size, 0);
  } finally {
    await runtime.close();
  }
});
test('XML workers cannot inherit process preloads or leak document text through sanitized errors', async () => {
  const original = process.env.NODE_OPTIONS,
    runtime = new Runtime(capture(settings), new AbortController().signal, () => true),
    xml = service(runtime),
    marker = 'private-document-sentinel';
  process.env.NODE_OPTIONS = '--require=/private/never-load-this-file';
  try {
    assert.ok(await xml.parse('<r>valid</r>'));
    await assert.rejects(
      xml.parse('<r>' + marker),
      (error: unknown) =>
        error instanceof KitError &&
        error.code === 'EK_XML_PARSE' &&
        !JSON.stringify(error.toSafeJSON()).includes(marker),
    );
    await assert.rejects(xml.parse('<r><?work data?></r>'), code('EK_UNSUPPORTED_CAPABILITY'));
  } finally {
    if (original === undefined) delete process.env.NODE_OPTIONS;
    else process.env.NODE_OPTIONS = original;
    await runtime.close();
  }
});
test('XSD never fabricates schema acceptance when its external validated backend is absent', async () => {
  const runtime = new Runtime(
      capture({ ...settings, xsdSchemaFiles: { invoice: '/offline/invoice.xsd' } }),
      new AbortController().signal,
      () => true,
    ),
    xml = service(runtime);
  try {
    await assert.rejects(
      xml.validateXsd(Buffer.from('<r/>'), 'invoice'),
      code('EK_UNSUPPORTED_CAPABILITY'),
    );
    await assert.rejects(xml.validateXsd(Buffer.from('<r/>'), 'unknown'), code('EK_XML_SCHEMA'));
    await assert.rejects(xml.validateXsd('<r/>' as never, 'invoice'), code('EK_XML_PARSE'));
  } finally {
    await runtime.close();
  }
});

test('Canceled external work retains its shared XML admission and shutdown ownership until actual settlement', async () => {
  const runtime = new Runtime(capture(settings), new AbortController().signal, () => true);
  let release!: () => void, entered!: () => void;
  const hold = new Promise<void>((resolve) => {
      release = resolve;
    }),
    started = new Promise<void>((resolve) => {
      entered = resolve;
    });
  const pending = runtime.external({ timeoutMs: 10 }, 0, async (signal) => {
    entered();
    await hold;
    assert.equal(signal.aborted, true);
  });
  await started;
  await assert.rejects(pending, code('EK_TIMEOUT'));
  assert.equal(runtime.active.size, 1);
  let settled = false;
  const closed = runtime.close().then(() => {
    settled = true;
  });
  await delay(5);
  assert.equal(settled, false);
  release();
  await closed;
  assert.equal(runtime.active.size, 0);
  assert.equal(settled, true);
});

test('XML worker and external cleanup never invoke later caller signal overrides', async () => {
  const runtime = new Runtime(capture(settings), new AbortController().signal, () => true);
  let effects = 0;
  try {
    const workerController = new AbortController();
    const parsed = service(runtime).parse('<r/>', { signal: workerController.signal });
    Object.defineProperty(workerController.signal, 'removeEventListener', {
      value: () => {
        effects++;
      },
    });
    assert.ok(Object.isFrozen((await parsed).root));
    assert.equal(runtime.active.size, 0);
    const externalController = new AbortController();
    const external = runtime.external({ signal: externalController.signal }, 0, async () => 42);
    Object.defineProperty(externalController.signal, 'removeEventListener', {
      value: () => {
        effects++;
      },
    });
    assert.equal(await external, 42);
    assert.equal(runtime.active.size, 0);
    assert.equal(effects, 0);
  } finally {
    await runtime.close();
  }
});

test('XML rejects proxy operation controls and excessive signal ancestry without executing traps', async () => {
  const runtime = new Runtime(capture(settings), new AbortController().signal, () => true);
  let effects = 0;
  const proxy = new Proxy(
    {},
    {
      getPrototypeOf() {
        effects++;
        return Object.prototype;
      },
    },
  );
  const controller = new AbortController();
  let parent: object = AbortSignal.prototype;
  for (let index = 0; index < 65; index++) parent = Object.create(parent) as object;
  Object.setPrototypeOf(controller.signal, parent);
  try {
    assert.throws(() => operation(proxy, 2000), code('EK_CONFIG_INVALID'));
    await assert.rejects(service(runtime).parse('<r/>', proxy), code('EK_CONFIG_INVALID'));
    assert.throws(() => operation({ signal: controller.signal }, 2000), code('EK_CONFIG_INVALID'));
    assert.equal(effects, 0);
    assert.equal(runtime.active.size, 0);
  } finally {
    await runtime.close();
  }
});

test('XML native cancellation survives caller hook replacement and retains actual work ownership', async () => {
  const runtime = new Runtime(capture(settings), new AbortController().signal, () => true);
  let effects = 0,
    release!: () => void,
    entered!: () => void;
  const hold = new Promise<void>((resolve) => {
    release = resolve;
  });
  const started = new Promise<void>((resolve) => {
    entered = resolve;
  });
  try {
    const controller = new AbortController();
    const pending = runtime.external({ signal: controller.signal }, 0, async (signal) => {
      entered();
      await hold;
      assert.equal(signal.aborted, true);
    });
    await started;
    Object.defineProperty(controller.signal, 'removeEventListener', {
      value: () => {
        effects++;
      },
    });
    controller.abort();
    await assert.rejects(pending, code('EK_ABORTED'));
    assert.equal(runtime.active.size, 1);
    release();
    await runtime.close();
    assert.equal(runtime.active.size, 0);
    assert.equal(effects, 0);
  } finally {
    release();
    await runtime.close();
  }
});
