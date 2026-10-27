// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { XML_CAPABILITY } from '../../dist/index.js';
import type { XmlService, XmlOptions, DataXmlPluginSettings } from '../../dist/index.js';
export function contract(service: XmlService, settings: DataXmlPluginSettings) {
  const options: XmlOptions = {
    forbidDtd: true,
    externalEntities: false,
    namespaceMode: 'expanded',
  };
  // @ts-expect-error Untrusted document types cannot enable DTD resolution.
  const unsafe: XmlOptions = { forbidDtd: false };
  // @ts-expect-error XSD schema locations are startup-owned, not operation request URLs.
  service.validateXsd(new Uint8Array(), { url: 'https://invalid.example/schema.xsd' });
  return { capability: XML_CAPABILITY, parsed: service.parse('<r/>', options), settings, unsafe };
}
