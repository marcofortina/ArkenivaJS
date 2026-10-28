// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { SaxesParser } from 'saxes';
import type { QualifiedName } from './catalog.js';
import { inspectXml } from './xml.js';
import { failure } from './validation.js';

/** Admit one qualified SOAP payload before the separate native SOAP decoder handles its content. */
export function inspectEnvelope(
  source: string,
  protocol: '1.1' | '1.2',
  maxBytes: number,
  expected?: readonly QualifiedName[],
  allowFault = true,
): QualifiedName {
  try {
    const inventory = inspectXml(source, maxBytes),
      namespace =
        protocol === '1.1'
          ? 'http://schemas.xmlsoap.org/soap/envelope/'
          : 'http://www.w3.org/2003/05/soap-envelope';
    if (inventory.root.local !== 'Envelope' || inventory.root.uri !== namespace) throw failure();
    const parser = new SaxesParser({ xmlns: true });
    let depth = 0,
      body = 0,
      header = 0,
      inBody = false,
      payload: QualifiedName | undefined;
    parser.on('opentag', (tag) => {
      depth++;
      if (depth === 2) {
        if (tag.uri !== namespace) throw failure();
        if (tag.local === 'Header') {
          if (++header > 1 || body) throw failure();
        } else if (tag.local === 'Body') {
          if (++body > 1) throw failure();
          inBody = true;
        } else throw failure();
      } else if (depth === 3 && inBody) {
        if (payload) throw failure();
        payload = Object.freeze({ local: tag.local, uri: tag.uri });
        const fault = tag.local === 'Fault' && tag.uri === namespace;
        if (
          (fault && !allowFault) ||
          (!fault &&
            expected &&
            !expected.some((value) => value.local === tag.local && value.uri === tag.uri))
        )
          throw failure();
      }
    });
    parser.on('closetag', () => {
      if (depth-- === 2) inBody = false;
    });
    const content = (text: string) => {
      if (depth <= 2 && text.trim()) throw failure();
    };
    parser.on('text', content);
    parser.on('cdata', content);
    parser.write(source).close();
    if (body !== 1 || !payload) throw failure();
    return payload;
  } catch {
    throw failure('EK_SOAP_SCHEMA');
  }
}
