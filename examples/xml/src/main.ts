// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { fileURLToPath, pathToFileURL } from 'node:url';
import { createApplication } from '@arkenivajs/core';
import { dataXmlPlugin, XML_CAPABILITY } from '@arkenivajs/data-xml';
import type { DataXmlPluginSettings, XmlService } from '@arkenivajs/data-xml';

/** The example alone opts into its static offline fixtures; application requests never choose files. */
export function fixtureSettings(xsd = false): DataXmlPluginSettings {
  return {
    defaults: { maxBytes: 65536, maxDepth: 32, maxAttributes: 128 },
    policy: { maxConcurrent: 1, timeoutMs: 5000, maxInputBytes: 65536, maxOutputBytes: 262144 },
    ...(xsd
      ? {
          xsdSchemaFiles: {
            invoice: fileURLToPath(new URL('../test/fixtures/invoice.xsd', import.meta.url)),
            invoiceTypes: fileURLToPath(new URL('../test/fixtures/types.xsd', import.meta.url)),
          },
        }
      : {}),
  };
}
export async function runXmlExample() {
  const app = await createApplication({
    service: { name: 'xml-example', version: '0.1.0', environment: 'test' },
    plugins: [dataXmlPlugin(fixtureSettings())],
  });
  try {
    await app.start();
    const xml = app.resolve<XmlService>(XML_CAPABILITY),
      document = await xml.parse(
        '<i:invoice xmlns:i="urn:invoice" id="001">before<i:line>Ελληνικά שלום</i:line>after</i:invoice>',
        { namespaceMode: 'expanded' },
      );
    const text = await xml.stringify(document, { namespaceMode: 'expanded' });
    return {
      document,
      roundtrip: await xml.parse(text, { namespaceMode: 'expanded' }),
      outputBytes: Buffer.byteLength(text),
    };
  } finally {
    await app.stop();
  }
}
export async function runXsdExample() {
  const app = await createApplication({
    service: { name: 'xsd-example', version: '0.1.0', environment: 'test' },
    plugins: [dataXmlPlugin(fixtureSettings(true))],
  });
  try {
    await app.start();
    const xml = app.resolve<XmlService>(XML_CAPABILITY);
    const valid = await xml.validateXsd(
      Buffer.from(
        '<invoice xmlns="urn:arkenivajs:invoice"><id>001</id><amount>12.50</amount></invoice>',
      ),
      'invoice',
    );
    const invalid = await xml.validateXsd(
      Buffer.from(
        '<invoice xmlns="urn:arkenivajs:invoice"><id>001</id><amount>invalid-decimal</amount></invoice>',
      ),
      'invoice',
    );
    return { valid, invalid };
  } finally {
    await app.stop();
  }
}
if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  if (process.argv.includes('--xsd')) {
    const result = await runXsdExample();
    console.log(JSON.stringify({ valid: result.valid.valid, invalid: result.invalid.valid }));
  } else {
    const result = await runXmlExample();
    console.log(
      JSON.stringify({
        roundtripEqual: JSON.stringify(result.document) === JSON.stringify(result.roundtrip),
        outputBytes: result.outputBytes,
      }),
    );
  }
}
