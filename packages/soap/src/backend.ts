// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { WSDL, Client } from 'soap';
import type { IHttpClient, IOptions } from 'soap';
import { inspectWsdl } from './xml.js';
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
