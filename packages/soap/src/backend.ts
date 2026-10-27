// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { WSDL, Client } from 'soap';
import type { IHttpClient, IOptions } from 'soap';
import { dirname, isAbsolute, relative, resolve } from 'node:path';
import { inspectWsdl, inspectXml } from './xml.js';
import { importedPath } from './assets.js';
import type { ContractAssets } from './assets.js';
import { failure } from './validation.js';

/** Contract construction itself may not obtain a URL or silently read an unregistered include. */
const deniedTransport: IHttpClient = {
  request() {
    throw failure();
  },
};
export async function nativeWsdl(source: string): Promise<WSDL> {
  const inventory = inspectWsdl(source);
  if (inventory.imports.length) throw failure('EK_UNSUPPORTED_CAPABILITY');
  const options: IOptions = {
    httpClient: deniedTransport,
    disableCache: true,
    handleNilAsNull: true,
    returnFault: true,
    ignoredNamespaces: { namespaces: [], override: true },
  };
  const native = new WSDL(source, '/offline/contract.wsdl', options);
  await new Promise<void>((resolve, reject) =>
    native.onReady((error) => (error ? reject(failure()) : resolve())),
  );
  return native;
}
/** Return the actual approved constructor instance, preserving native identity and serialization. */
export async function nativeClient(source: string, endpoint: string): Promise<Client> {
  const contract = await nativeWsdl(source);
  return new Client(contract, endpoint, { httpClient: deniedTransport, disableCache: true });
}

/** Populate the actual native cache in dependency order; a cache miss fails before native I/O. */
export async function nativeGraph(assets: ContractAssets): Promise<WSDL> {
  const cache: Record<string, WSDL> = Object.create(null);
  if (
    !isAbsolute(assets.entry) ||
    resolve(assets.entry) !== assets.entry ||
    !assets.documents.length ||
    assets.documents.length > 32 ||
    assets.documents.at(-1)?.path !== assets.entry
  )
    throw failure();
  let total = 0;
  for (const document of assets.documents) {
    const inside = relative(dirname(assets.entry), document.path);
    if (
      !isAbsolute(document.path) ||
      resolve(document.path) !== document.path ||
      !inside ||
      inside === '..' ||
      inside.startsWith('../') ||
      isAbsolute(inside) ||
      Object.hasOwn(cache, document.path)
    )
      throw failure();
    const inventory =
      document.path === assets.entry ? inspectWsdl(document.source) : inspectXml(document.source);
    if (
      document.path !== assets.entry &&
      !(
        (inventory.root.local === 'schema' &&
          inventory.root.uri === 'http://www.w3.org/2001/XMLSchema') ||
        (inventory.root.local === 'definitions' &&
          inventory.root.uri === 'http://schemas.xmlsoap.org/wsdl/')
      )
    )
      throw failure();
    total += Buffer.byteLength(document.source);
    if (
      total > 8388608 ||
      inventory.imports.some(
        (reference) =>
          !Object.hasOwn(cache, importedPath(document.path, reference, dirname(assets.entry))),
      )
    )
      throw failure();
    // The native implementation consumes this cache option but omits it from its public declaration.
    const options: IOptions & { WSDL_CACHE: Record<string, WSDL> } = {
      httpClient: deniedTransport,
      disableCache: true,
      handleNilAsNull: true,
      returnFault: true,
      strict: true,
      WSDL_CACHE: cache,
      ignoredNamespaces: { namespaces: [], override: true },
      wsdl_options: {
        overrideImportLocation(path: string, source: string, reference: string): string {
          const expected = importedPath(source, reference, dirname(assets.entry));
          if (path !== expected || !Object.hasOwn(cache, expected)) throw failure();
          return expected;
        },
      },
    };
    const native = new WSDL(document.source, document.path, options);
    await new Promise<void>((resolve, reject) =>
      native.onReady((error) => (error ? reject(failure()) : resolve())),
    );
    cache[document.path] = native;
  }
  const result = cache[assets.entry];
  if (!result) throw failure();
  Object.freeze(cache);
  return result;
}
