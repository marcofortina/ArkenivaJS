// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { dataXmlPlugin, XML_CAPABILITY } from '@arkenivajs/data-xml';
import { runPureWorker } from './pure-worker.mjs';
import { nativeXml, verifyXml, xmlSettings, xmlWorkload } from './xml-workload.mjs';
import { assertXmlAssets } from './xml-xsd.mjs';

let active;

runPureWorker({
  name: 'xml',
  asynchronous: true,
  iterations: 100,
  warmupIterations: 20,
  retainRawSamples: true,
  native: nativeXml,
  async framework(fixture) {
    if (fixture.xsd) await assertXmlAssets(fixture.xsd);
    return {
      plugin: dataXmlPlugin({
        ...xmlSettings,
        ...(fixture.xsd ? { xsdSchemaFiles: fixture.xsd.schemas } : {}),
      }),
      key: XML_CAPABILITY,
    };
  },
  verify: verifyXml,
  workload(service, fixture) {
    active = xmlWorkload(service, fixture);
    return active.workload;
  },
  complete(_service, { measure, records }) {
    return measure ? active.complete(records) : undefined;
  },
});
