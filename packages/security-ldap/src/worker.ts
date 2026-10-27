// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import net from 'node:net';
import tls from 'node:tls';
import { performance } from 'node:perf_hooks';
import { Client, EqualityFilter, InvalidCredentialsError } from 'ldapts';
import type { Entry, Filter } from 'ldapts';
import type { LdapEntry, LdapGroup, LdapUser, WorkerInput } from './contracts.js';
import { boundFilter } from './filter.js';
import { attribute, failure, text } from './validation.js';

/** This process owns all directory sockets and never inherits native diagnostic settings. */
const sockets = new Set<net.Socket>(),
  clients = new Set<Client>();
let wireBytes = 0,
  outputBytes = 0;
function send(value: object): Promise<void> {
  return new Promise((resolve, reject) => {
    if (!process.send || !process.connected) {
      reject(failure());
      return;
    }
    process.send(value, (error) => (error ? reject(failure()) : resolve()));
  });
}
function own<T extends net.Socket>(socket: T): T {
  sockets.add(socket);
  socket.once('close', () => sockets.delete(socket));
  socket.prependListener('data', (chunk: Buffer) => {
    wireBytes += chunk.length;
    if (wireBytes > 8 * 1024 * 1024) {
      for (const item of sockets) item.destroy();
    }
  });
  return socket;
}
async function connect(
  input: WorkerInput,
  dn: string,
  password: string,
  userBind = false,
): Promise<Client> {
  const hostname = new URL(input.url).hostname.replace(/^\[|\]$/g, ''),
    tlsOptions: tls.ConnectionOptions = {
      rejectUnauthorized: true,
      minVersion: 'TLSv1.2',
      ...(input.ca === undefined ? {} : { ca: input.ca }),
      ...(net.isIP(hostname) ? {} : { servername: hostname }),
      checkServerIdentity: (_host, certificate) => tls.checkServerIdentity(hostname, certificate),
    };
  let connected = false,
    upgraded = false;
  const createConnection: typeof net.connect = (...args: unknown[]) => {
    if (connected) throw failure('EK_LDAP_CONNECT');
    connected = true;
    return own(Reflect.apply(net.connect, net, args) as net.Socket);
  };
  const createSecureConnection: typeof tls.connect = (...args: unknown[]) => {
    if (input.startTls) {
      if (!connected || upgraded) throw failure('EK_LDAP_CONNECT');
      upgraded = true;
    } else {
      if (connected) throw failure('EK_LDAP_CONNECT');
      connected = true;
    }
    return own(Reflect.apply(tls.connect, tls, args) as tls.TLSSocket);
  };
  const client = new Client({
    url: input.url,
    timeout: input.timeoutMs,
    connectTimeout: input.timeoutMs,
    autoRebind: false,
    createConnection,
    createSecureConnection,
    ...(input.startTls ? {} : { tlsOptions }),
  });
  clients.add(client);
  if (input.startTls) {
    try {
      await client.startTLS(tlsOptions);
    } catch {
      throw failure('EK_LDAP_CONNECT');
    }
  }
  await send({ type: 'binding' });
  const started = performance.now();
  try {
    await client.bind(dn, password);
  } catch (error) {
    if (userBind && error instanceof InvalidCredentialsError) throw error;
    throw failure(client.isConnected ? 'EK_LDAP_BIND' : 'EK_LDAP_CONNECT');
  } finally {
    await send({ type: 'measure', name: 'bind', value: Math.max(0, performance.now() - started) });
  }
  if (!client.isBound) throw failure('EK_LDAP_BIND');
  return client;
}
function project(entry: Entry, approved: readonly string[]): LdapEntry {
  const attributes: Record<string, readonly string[]> = Object.create(null);
  if (Object.keys(entry).length > 65) throw failure('EK_LDAP_SEARCH');
  for (const [key, raw] of Object.entries(entry)) {
    if (key === 'dn') continue;
    const name = attribute(key);
    if (!approved.includes(name) || Object.hasOwn(attributes, name))
      throw failure('EK_LDAP_SEARCH');
    const values = Array.isArray(raw) ? raw : [raw];
    if (values.length > 128) throw failure('EK_LDAP_SEARCH');
    attributes[name] = values.map((value: unknown) => {
      const decoded = Buffer.isBuffer(value)
        ? new TextDecoder('utf-8', { fatal: true }).decode(value)
        : value;
      const result = text(decoded, 16384, true);
      outputBytes += Buffer.byteLength(result);
      if (outputBytes > 4 * 1024 * 1024) throw failure('EK_LDAP_SEARCH');
      return result;
    });
  }
  return { dn: text(entry.dn, 2048), attributes };
}
async function* search(
  client: Client,
  baseDn: string,
  filter: Filter,
  attributes: readonly string[],
  maximum: number,
  pageSize: number,
): AsyncGenerator<LdapEntry> {
  let count = 0;
  if (!client.isBound) throw failure('EK_LDAP_BIND');
  try {
    for await (const page of client.searchPaginated(baseDn, {
      filter,
      attributes: [...attributes],
      explicitBufferAttributes: [...attributes],
      scope: 'sub',
      derefAliases: 'never',
      paged: { pageSize },
      sizeLimit: maximum + 1,
    })) {
      await send({ type: 'measure', name: 'search', value: 1 });
      if (
        !client.isBound ||
        page.searchReferences.length ||
        page.searchEntries.length > maximum + 1
      )
        throw failure('EK_LDAP_SEARCH');
      for (const entry of page.searchEntries) {
        if (++count > maximum) throw failure('EK_LDAP_SEARCH');
        yield project(entry, attributes);
      }
    }
  } catch {
    throw failure('EK_LDAP_SEARCH');
  }
}
async function find(client: Client, input: WorkerInput): Promise<LdapUser | null> {
  const found: LdapEntry[] = [];
  for await (const entry of search(
    client,
    input.baseDn,
    boundFilter(input.template, { username: input.username! }, input.allowedAttributes),
    input.allowedAttributes,
    2,
    2,
  ))
    found.push(entry);
  if (found.length > 1) throw failure('EK_LDAP_SEARCH');
  const entry = found[0];
  if (!entry) return null;
  const uid = entry.attributes.uid ?? entry.attributes.samaccountname;
  if (!uid || uid.length !== 1 || !uid[0]) throw failure('EK_LDAP_SEARCH');
  return { ...entry, uid: uid[0] };
}
async function groups(client: Client, input: WorkerInput): Promise<readonly LdapGroup[]> {
  const visited = new Set<string>([input.userDn!]),
    result: LdapGroup[] = [];
  let current = [input.userDn!];
  for (let depth = 0; current.length; depth++) {
    await send({ type: 'measure', name: 'depth', value: depth });
    const next: string[] = [];
    for (const member of current) {
      for await (const entry of search(
        client,
        input.groupBase,
        new EqualityFilter({ attribute: 'member', value: member }),
        ['cn'],
        input.maxEntries,
        Math.min(100, input.maxEntries),
      )) {
        if (visited.has(entry.dn)) continue;
        if (
          depth >= input.maxDepth ||
          result.length >= input.maxEntries ||
          entry.attributes.cn?.length !== 1
        )
          throw failure('EK_LDAP_SEARCH');
        visited.add(entry.dn);
        next.push(entry.dn);
        result.push({ dn: entry.dn, name: text(entry.attributes.cn[0], 2048) });
      }
    }
    current = next;
  }
  return result;
}
async function work(input: WorkerInput): Promise<unknown> {
  const service = await connect(input, input.bindDn, input.bindPassword);
  if (input.operation === 'ping') return true;
  if (input.operation === 'find') return find(service, input);
  if (input.operation === 'groups') return groups(service, input);
  if (input.operation === 'verify') {
    const user = await find(service, input);
    if (!user) return false;
    try {
      await connect(input, user.dn, input.password!, true);
      return true;
    } catch (error) {
      if (error instanceof InvalidCredentialsError) return false;
      throw error;
    }
  }
  const query = input.query!;
  for await (const entry of search(
    service,
    query.baseDn,
    boundFilter(query.filter.template, query.filter.values, input.allowedAttributes),
    query.attributes,
    query.maxEntries!,
    query.pageSize!,
  )) {
    const acknowledgment = new Promise<void>((resolve) => process.once('message', () => resolve()));
    await send({ type: 'entry', entry });
    await acknowledgment;
  }
  return null;
}
process.once('message', (input: WorkerInput) => {
  void (async () => {
    let result: unknown, error: unknown;
    try {
      result = await work(input);
    } catch (caught) {
      error = caught;
    } finally {
      for (const client of clients) {
        try {
          await client.unbind();
        } catch {
          /* Socket destruction below completes physical cleanup. */
        }
      }
      for (const socket of sockets) socket.destroy();
    }
    // Native diagnostics and exception contents never cross the private result boundary.
    await send(
      error
        ? {
            type: 'error',
            kind:
              error instanceof Error && 'code' in error && typeof error.code === 'string'
                ? error.code
                : 'EK_LDAP_CONNECT',
          }
        : { type: 'result', value: result },
    );
    process.disconnect();
  })().catch(() => {
    for (const socket of sockets) socket.destroy();
    process.exitCode = 1;
    process.disconnect?.();
  });
});
process.once('disconnect', () => {
  for (const socket of sockets) socket.destroy();
});
