// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { dataXmlPlugin, XML_CAPABILITY } from '@arkenivajs/data-xml';
import { runPureWorker } from './pure-worker.mjs';
import { nativeXml, verifyXml, xmlSettings } from './xml-workload.mjs';

runPureWorker({
  name: 'xml',
  native: nativeXml,
  framework: () => ({ plugin: dataXmlPlugin(xmlSettings), key: XML_CAPABILITY }),
  verify: verifyXml,
});
