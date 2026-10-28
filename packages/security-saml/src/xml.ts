// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { DOMParser } from '@xmldom/xmldom';
import { failure } from './validation.js';

export const NS = Object.freeze({
  metadata: 'urn:oasis:names:tc:SAML:2.0:metadata',
  protocol: 'urn:oasis:names:tc:SAML:2.0:protocol',
  assertion: 'urn:oasis:names:tc:SAML:2.0:assertion',
  signature: 'http://www.w3.org/2000/09/xmldsig#',
  redirect: 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect',
  post: 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST',
});
/** Bound the native parser's input before invoking its existing XML implementation. */
export function parse(input: string, maximum = 262144): Document {
  if (
    typeof input !== 'string' ||
    Buffer.byteLength(input) > maximum ||
    !input ||
    Buffer.from(input).toString('utf8') !== input ||
    /<!\s*(?:DOCTYPE|ENTITY)/i.test(input) ||
    input.includes('\0')
  )
    throw failure('EK_SAML_ASSERTION');
  let document: Document;
  const reject = () => {
    throw failure('EK_SAML_ASSERTION');
  };
  try {
    document = new DOMParser({
      errorHandler: { warning: reject, error: reject, fatalError: reject },
    }).parseFromString(input, 'text/xml') as unknown as Document;
  } catch {
    throw failure('EK_SAML_ASSERTION');
  }
  const root = document.documentElement;
  if (!root || document.doctype) throw failure('EK_SAML_ASSERTION');
  const stack: { node: Node; depth: number }[] = [{ node: root, depth: 0 }],
    ids = new Set<string>();
  let nodes = 0;
  while (stack.length) {
    const { node, depth } = stack.pop()!;
    if (++nodes > 8192 || depth > 32) throw failure('EK_SAML_ASSERTION');
    if (node.nodeType === 1) {
      const element = node as Element;
      if (element.attributes.length > 32) throw failure('EK_SAML_ASSERTION');
      for (const name of ['ID', 'Id', 'id'])
        if (element.hasAttribute(name)) {
          const id = element.getAttribute(name)!;
          if (!id || id.length > 256 || ids.has(id)) throw failure('EK_SAML_SIGNATURE');
          ids.add(id);
        }
    }
    for (let child = node.lastChild; child; child = child.previousSibling)
      stack.push({ node: child, depth: depth + 1 });
  }
  return document;
}
export function children(
  parent: Element,
  namespace: string,
  localName: string,
): readonly Element[] {
  const result: Element[] = [];
  for (let node = parent.firstChild; node; node = node.nextSibling)
    if (node.nodeType === 1) {
      const element = node as Element;
      if (element.namespaceURI === namespace && element.localName === localName)
        result.push(element);
    }
  return result;
}
export function one(parent: Element, namespace: string, localName: string): Element {
  const result = children(parent, namespace, localName);
  if (result.length !== 1) throw failure('EK_SAML_ASSERTION');
  return result[0]!;
}
export function content(element: Element, maximum = 4096): string {
  for (let node = element.firstChild; node; node = node.nextSibling)
    if (node.nodeType !== 3 && node.nodeType !== 4) throw failure('EK_SAML_ASSERTION');
  const value = element.textContent;
  if (
    !value ||
    Buffer.byteLength(value) > maximum ||
    [...value].some((character) => character.charCodeAt(0) < 32 || character.charCodeAt(0) === 127)
  )
    throw failure('EK_SAML_ASSERTION');
  return value;
}
export function strongSignatures(root: Element): void {
  const signatures = root.getElementsByTagNameNS(NS.signature, 'Signature');
  if (signatures.length < 1 || signatures.length > 2) throw failure('EK_SAML_SIGNATURE');
  const algorithms = new Set([
    'http://www.w3.org/2001/04/xmldsig-more#rsa-sha256',
    'http://www.w3.org/2001/04/xmldsig-more#rsa-sha384',
    'http://www.w3.org/2001/04/xmldsig-more#rsa-sha512',
  ]);
  const digests = new Set([
    'http://www.w3.org/2001/04/xmlenc#sha256',
    'http://www.w3.org/2001/04/xmldsig-more#sha384',
    'http://www.w3.org/2001/04/xmlenc#sha512',
  ]);
  for (let index = 0; index < signatures.length; index++) {
    const signature = signatures.item(index)!,
      info = one(signature, NS.signature, 'SignedInfo');
    if (!algorithms.has(one(info, NS.signature, 'SignatureMethod').getAttribute('Algorithm') ?? ''))
      throw failure('EK_SAML_SIGNATURE');
    const references = children(info, NS.signature, 'Reference');
    if (
      references.length !== 1 ||
      !/^#[A-Za-z_][A-Za-z0-9_.-]{0,255}$/.test(references[0]!.getAttribute('URI') ?? '') ||
      !digests.has(
        one(references[0]!, NS.signature, 'DigestMethod').getAttribute('Algorithm') ?? '',
      )
    )
      throw failure('EK_SAML_SIGNATURE');
  }
}
