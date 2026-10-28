// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { SaxesParser } from 'saxes';
import { failure } from './validation.js';
const namespace =
  'http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd';

/** Compare native SAX events for a provider-owned token without implementing a WS-Security algorithm. */
function transcript(source: string, envelope: boolean): string {
  const parser = new SaxesParser({ xmlns: true }),
    events: unknown[] = [];
  let depth = 0,
    start = 0,
    found = 0,
    inHeader = false;
  parser.on('opentag', (tag) => {
    depth++;
    if (envelope && depth === 2)
      inHeader =
        tag.local === 'Header' &&
        [
          'http://schemas.xmlsoap.org/soap/envelope/',
          'http://www.w3.org/2003/05/soap-envelope',
        ].includes(tag.uri);
    if (tag.local === 'Security' && tag.uri === namespace) {
      if (++found !== 1 || depth !== (envelope ? 3 : 1) || (envelope && !inHeader))
        throw failure('EK_SOAP_SCHEMA');
      start = depth;
    }
    if (start) {
      if (events.length > 256) throw failure('EK_SOAP_SCHEMA');
      events.push([
        'open',
        tag.uri,
        tag.local,
        Object.values(tag.attributes)
          .filter((attribute) => attribute.uri !== 'http://www.w3.org/2000/xmlns/')
          .map((attribute) => [attribute.uri, attribute.local, attribute.value])
          .sort((a, b) => JSON.stringify(a).localeCompare(JSON.stringify(b))),
      ]);
    }
  });
  parser.on('closetag', (tag) => {
    if (start) events.push(['close', tag.uri, tag.local]);
    if (depth-- === start) start = 0;
  });
  const content = (text: string) => {
    if (start) events.push(['text', text]);
  };
  parser.on('text', content);
  parser.on('cdata', content);
  parser.write(source).close();
  if (found !== 1) throw failure('EK_SOAP_SCHEMA');
  return JSON.stringify(events);
}
export function verifySecurityHeader(source: string, nativeToken: string | undefined): void {
  try {
    if (
      !nativeToken ||
      nativeToken.length > 16384 ||
      transcript(source, true) !== transcript(nativeToken, false)
    )
      throw failure();
  } catch {
    throw failure('EK_SOAP_SCHEMA');
  }
}
