// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import assert from 'node:assert/strict';
import { test } from 'node:test';
import { AsyncLocalStorage } from 'node:async_hooks';
import net from 'node:net';
import dgram from 'node:dgram';
import { once } from 'node:events';
import { setTimeout as delay } from 'node:timers/promises';
import { mkdtemp, lstat, readFile, writeFile, unlink, symlink, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import fc from 'fast-check';
import { createApplication, KitError } from '@arkenivajs/core';
import type { Application } from '@arkenivajs/core';
import { socketPlugin, SOCKET_CAPABILITY } from '../../dist/index.js';
import type {
  SocketService,
  SocketPeer,
  SocketServerHandle,
  UdpDatagram,
  SocketPluginOptions,
} from '../../dist/index.js';

const code = (expected: string) => (cause: unknown) =>
  cause instanceof KitError && cause.code === expected;
const echo = async (peer: SocketPeer) => {
  for await (const bytes of peer.chunks()) await peer.send(bytes);
  await peer.end();
};
async function app(options?: SocketPluginOptions, environment: 'test' | 'production' = 'test') {
  const application = await createApplication({
    service: { name: 'socket-fixture', version: '1.0.0', environment },
    plugins: [socketPlugin(options)],
  });
  await application.start();
  return { application, service: application.resolve<SocketService>(SOCKET_CAPABILITY) };
}
async function connect(handle: SocketServerHandle) {
  const bound = handle.boundAddress!,
    client = bound.path
      ? net.connect(bound.path)
      : net.connect({ host: bound.network!.address, port: bound.network!.port });
  await once(client, 'connect');
  return client;
}
async function exchange(handle: SocketServerHandle, bytes = Buffer.from([0, 1, 2, 255])) {
  const client = await connect(handle);
  client.end(bytes);
  const received: Buffer[] = [];
  for await (const chunk of client) received.push(chunk);
  return Buffer.concat(received);
}
async function waitFor(check: () => boolean) {
  for (let i = 0; i < 100; i++) {
    if (check()) return;
    await delay(5);
  }
  assert.fail('The native fixture did not reach its expected state');
}
async function stop(application: Application) {
  await application.stop({ timeoutMs: 1000 });
}

test('TCP payload bounds and copies use native byte slots without evaluating instance metadata', async () => {
  const { application, service } = await app();
  let resolve!: (peer: SocketPeer) => void,
    effects = 0;
  const ready = new Promise<SocketPeer>((done) => {
    resolve = done;
  });
  const listener = service.createTcpServer(
    { name: 'native-bytes', port: 0, maxPendingWriteBytes: 4 },
    (peer) => {
      resolve(peer);
    },
  );
  let client: net.Socket | undefined, owned: SocketPeer | undefined;
  try {
    await listener.start();
    client = await connect(listener);
    const peer = (owned = await ready);
    const oversized = new Uint8Array(5);
    Object.defineProperty(oversized, 'length', {
      get() {
        effects++;
        return 0;
      },
    });
    await assert.rejects(peer.send(oversized), code('EK_SOCKET_CAPACITY'));
    for (const value of [
      new Uint8Array(new SharedArrayBuffer(4)),
      new Proxy(new Uint8Array(4), {}),
    ])
      await assert.rejects(peer.send(value), code('EK_SOCKET_CAPACITY'));
    const payload = new Uint8Array([99, 0, 1, 254, 255, 99]).subarray(1, 5);
    for (const field of [
      'length',
      'byteLength',
      'buffer',
      'byteOffset',
      Symbol.iterator,
      'valueOf',
    ])
      Object.defineProperty(payload, field, {
        get() {
          effects++;
          throw new Error('Byte metadata must not execute');
        },
      });
    const received: Buffer[] = [];
    client.on('data', (chunk: Buffer) => received.push(chunk));
    await peer.send(payload);
    await peer.end();
    await once(client, 'end');
    assert.deepEqual(Buffer.concat(received), Buffer.from([0, 1, 254, 255]));
    assert.equal(effects, 0);
    assert.equal(listener.stats().sentApplicationBytes, 4);
  } finally {
    owned?.close();
    client?.destroy();
    await stop(application);
  }
});

test('UDP outbound payloads preserve native bytes and reject hidden size overflow before sending', async () => {
  const { application, service } = await app(),
    client = dgram.createSocket('udp4');
  let effects = 0;
  try {
    client.bind(0, '127.0.0.1');
    await once(client, 'listening');
    const target = { address: '127.0.0.1', family: 'IPv4' as const, port: client.address().port };
    const listener = service.createUdpServer(
      {
        name: 'native-outbound',
        port: 0,
        family: 'udp4',
        maxReplyBytes: 4,
        allowOutboundDestinations: true,
        destinationAllowlist: ['127.0.0.1:' + target.port],
      },
      () => undefined,
    );
    await listener.start();
    const oversized = new Uint8Array(5);
    Object.defineProperties(oversized, {
      byteLength: {
        get() {
          effects++;
          return 0;
        },
      },
      length: {
        get() {
          effects++;
          return 0;
        },
      },
    });
    await assert.rejects(listener.sendTo(target, oversized), code('EK_SOCKET_DATAGRAM'));
    for (const value of [
      new Uint8Array(new SharedArrayBuffer(4)),
      new Proxy(new Uint8Array(4), {}),
    ])
      await assert.rejects(listener.sendTo(target, value), code('EK_SOCKET_DATAGRAM'));
    const payload = new Uint8Array([99, 0, 1, 254, 255, 99]).subarray(1, 5);
    for (const field of [
      'length',
      'byteLength',
      'buffer',
      'byteOffset',
      Symbol.iterator,
      'valueOf',
    ])
      Object.defineProperty(payload, field, {
        get() {
          effects++;
          throw new Error('Byte metadata must not execute');
        },
      });
    const received = once(client, 'message');
    await listener.sendTo(target, payload);
    assert.deepEqual((await received)[0], Buffer.from([0, 1, 254, 255]));
    assert.equal(effects, 0);
    assert.equal(listener.stats().sentApplicationBytes, 4);
  } finally {
    client.close();
    await stop(application);
  }
});

test('UDP reply amplification uses actual native payload size before reserving or sending bytes', async () => {
  const { application, service } = await app(),
    client = dgram.createSocket('udp4');
  let effects = 0,
    resolve!: () => void,
    reject!: (error: unknown) => void;
  const handled = new Promise<void>((done, fail) => {
    resolve = done;
    reject = fail;
  });
  try {
    const listener = service.createUdpServer(
      {
        name: 'native-replies',
        port: 0,
        family: 'udp4',
        maxReplyBytes: 4,
        maxReplyAmplificationFactor: 1,
      },
      async (datagram, socket) => {
        try {
          const oversized = new Uint8Array(2);
          Object.defineProperty(oversized, 'length', {
            get() {
              effects++;
              return 0;
            },
          });
          await assert.rejects(socket.reply(datagram, oversized), code('EK_SOCKET_DATAGRAM'));
          const payload = new Uint8Array([42]);
          for (const field of [
            'length',
            'byteLength',
            'buffer',
            'byteOffset',
            Symbol.iterator,
            'valueOf',
          ])
            Object.defineProperty(payload, field, {
              get() {
                effects++;
                throw new Error('Byte metadata must not execute');
              },
            });
          await socket.reply(datagram, payload);
          await assert.rejects(
            socket.reply(datagram, new Uint8Array([42])),
            code('EK_SOCKET_DATAGRAM'),
          );
          resolve();
        } catch (error) {
          reject(error);
        }
      },
    );
    await listener.start();
    const received = once(client, 'message');
    client.send(Buffer.from([1]), listener.boundAddress!.network!.port, '127.0.0.1');
    await handled;
    assert.deepEqual((await received)[0], Buffer.from([42]));
    assert.equal(effects, 0);
    assert.equal(listener.stats().sentApplicationBytes, 1);
  } finally {
    client.close();
    await stop(application);
  }
});

test('TCP native byte streams preserve arbitrary bytes, half-close and accurate payload counters', async () => {
  const { application, service } = await app();
  try {
    const listener = service.createTcpServer({ name: 'echo', port: 0 }, echo);
    assert.equal(listener.state, 'CREATED');
    assert.equal(listener.boundAddress, undefined);
    const bound = await listener.start();
    assert.equal(bound.network!.address, '127.0.0.1');
    assert.notEqual(bound.network!.port, 0);
    assert.equal(await listener.start(), bound);
    const payload = Buffer.from([0, 1, 13, 10, 255, 0, 254]);
    assert.deepEqual(await exchange(listener, payload), payload);
    await waitFor(() => listener.stats().activeConnections === 0);
    assert.equal(listener.stats().receivedApplicationBytes, payload.length);
    assert.equal(listener.stats().sentApplicationBytes, payload.length);
    assert.equal(listener.stats().acceptedConnections, 1);
    await listener.stop();
    await listener.stop();
    assert.equal(listener.state, 'CLOSED');
    await assert.rejects(listener.start(), code('EK_SOCKET_STATE'));
  } finally {
    await stop(application);
  }
});

test('Stream readers are exclusive and peer faults remain local to their own connection', async () => {
  const { application, service } = await app();
  let calls = 0,
    rejected = false;
  try {
    const listener = service.createTcpServer({ name: 'isolated', port: 0 }, async (peer) => {
      calls++;
      if (calls === 1) throw new Error('Private application payload');
      const reader = peer.chunks();
      assert.throws(() => peer.chunks(), code('EK_SOCKET_STATE'));
      rejected = true;
      for await (const bytes of reader) await peer.send(bytes);
      await peer.end();
    });
    await listener.start();
    const first = await connect(listener);
    first.on('error', () => undefined);
    await once(first, 'close');
    assert.deepEqual(await exchange(listener), Buffer.from([0, 1, 2, 255]));
    assert.equal(rejected, true);
    assert.equal(listener.state, 'LISTENING');
    assert.equal(listener.stats().errors, 1);
  } finally {
    await stop(application);
  }
});

test('Connection admission, idle deadlines and bounded writes reject overload on actual sockets', async () => {
  const { application, service } = await app();
  let peer: SocketPeer | undefined;
  try {
    const listener = service.createTcpServer(
      { name: 'limited', port: 0, maxConnections: 1, idleTimeoutMs: 100, maxPendingWriteBytes: 4 },
      (value) => {
        peer = value;
      },
    );
    await listener.start();
    const first = await connect(listener);
    first.on('error', () => undefined);
    await waitFor(() => peer !== undefined);
    await assert.rejects(peer!.send(Buffer.alloc(5)), code('EK_SOCKET_CAPACITY'));
    const second = await connect(listener);
    second.on('error', () => undefined);
    await once(second, 'close');
    assert.equal(listener.stats().rejectedConnections, 1);
    await once(first, 'close');
    await waitFor(() => peer!.signal.aborted);
    assert.ok(listener.stats().errors >= 1);
  } finally {
    await stop(application);
  }
});

test('Listener cancellation and bind conflicts close resources and never rebind failed handles', async () => {
  const { application, service } = await app();
  try {
    const first = service.createTcpServer({ name: 'owner', port: 0 }, echo);
    await first.start();
    const second = service.createTcpServer(
      { name: 'conflict', port: first.boundAddress!.network!.port },
      echo,
    );
    await assert.rejects(second.start(), code('EK_SOCKET_BIND'));
    assert.equal(second.state, 'FAILED');
    const controller = new AbortController();
    controller.abort();
    const canceled = service.createTcpServer({ name: 'cancel', port: 0 }, echo);
    await assert.rejects(canceled.start({ signal: controller.signal }), code('EK_ABORTED'));
    assert.equal(canceled.state, 'FAILED');
    assert.deepEqual(await exchange(first), Buffer.from([0, 1, 2, 255]));
  } finally {
    await stop(application);
  }
});

test('Static listeners bind before READY and startup failure rolls back earlier native endpoints', async () => {
  const external = net.createServer();
  await new Promise<void>((resolve) => external.listen(0, '127.0.0.1', resolve));
  const port = (external.address() as net.AddressInfo).port;
  const application = await createApplication({
    service: { name: 'rollback', version: '1.0.0', environment: 'test' },
    plugins: [
      socketPlugin({
        listeners: [
          { kind: 'tcp', options: { name: 'first', port: 0 }, handler: echo },
          { kind: 'tcp', options: { name: 'conflict', port }, handler: echo },
        ],
      }),
    ],
  });
  try {
    await assert.rejects(application.start());
    assert.equal(application.state, 'CLOSED');
  } finally {
    await application.stop().catch(() => undefined);
    await new Promise<void>((resolve) => external.close(() => resolve()));
  }
});

test('Managed socket services capture settings and isolate reused plugin lifetimes', async () => {
  const options = {
      listeners: [{ kind: 'tcp' as const, options: { name: 'static', port: 0 }, handler: echo }],
    },
    plugin = socketPlugin(options);
  options.listeners[0]!.options.name = 'changed';
  const config = {
      service: { name: 'reuse', version: '1.0.0', environment: 'test' as const },
      plugins: [plugin],
    },
    first = await createApplication(config),
    second = await createApplication(config);
  try {
    await first.start();
    await second.start();
    const a = first.resolve<SocketService>(SOCKET_CAPABILITY),
      b = second.resolve<SocketService>(SOCKET_CAPABILITY);
    assert.equal(a.list()[0]!.name, 'static');
    await stop(first);
    assert.throws(() => a.list(), code('EK_SOCKET_CLOSED'));
    assert.equal(b.list()[0]!.state, 'LISTENING');
    assert.throws(
      () => b.createTcpServer({ name: 'static', port: 0 }, echo),
      code('EK_SOCKET_CONFIG'),
    );
  } finally {
    await first.stop();
    await stop(second);
  }
});

test('All public configuration and operation bounds reject invalid input before native I/O', async () => {
  for (const options of [
    null,
    { unknown: true },
    { listeners: null },
    {
      listeners: [
        { kind: 'tcp', options: { name: 'bad', port: 1, idleTimeoutMs: 0 }, handler: echo },
      ],
    },
    {
      listeners: [
        {
          kind: 'udp',
          options: { name: 'bad', family: 'udp4', port: 1, allowOutboundDestinations: true },
          handler: () => undefined,
        },
      ],
    },
  ])
    assert.throws(() => socketPlugin(options as never), code('EK_SOCKET_CONFIG'));
  const { application, service } = await app(undefined, 'production');
  try {
    assert.throws(
      () => service.createTcpServer({ name: 'ephemeral', port: 0 }, echo),
      code('EK_SOCKET_CONFIG'),
    );
  } finally {
    await stop(application);
  }
});

test('Native UDP preserves datagram boundaries, zero-length messages and safe reply provenance', async () => {
  const { application, service } = await app();
  let saved: UdpDatagram | undefined;
  const client = dgram.createSocket('udp4');
  try {
    const listener = service.createUdpServer(
      { name: 'datagrams', family: 'udp4', port: 0 },
      async (value, server) => {
        saved = value;
        await assert.rejects(server.reply({ ...value }, value.bytes), code('EK_SOCKET_DATAGRAM'));
        await server.reply(value, value.bytes);
      },
    );
    await listener.start();
    const port = listener.boundAddress!.network!.port;
    for (const bytes of [Buffer.from([0, 1, 255]), Buffer.alloc(0), Buffer.from('separate')]) {
      const response = once(client, 'message');
      client.send(bytes, port, '127.0.0.1');
      assert.deepEqual((await response)[0], bytes);
    }
    await waitFor(() => listener.stats().sentApplicationBytes === 11);
    assert.equal(listener.stats().receivedApplicationBytes, 11);
    await delay(0);
    await assert.rejects(listener.reply(saved!, new Uint8Array()), code('EK_SOCKET_DATAGRAM'));
    await assert.rejects(
      listener.sendTo({ address: '127.0.0.1', family: 'IPv4', port }, Buffer.from('x')),
      code('EK_SOCKET_DATAGRAM'),
    );
  } finally {
    client.close();
    await stop(application);
  }
});

test('UDP cumulative amplification and explicit outbound destinations are enforced before sends', async () => {
  const { application, service } = await app();
  const client = dgram.createSocket('udp4');
  let checked = false;
  try {
    await new Promise<void>((resolve) => client.bind(0, '127.0.0.1', resolve));
    const target = client.address();
    const listener = service.createUdpServer(
      {
        name: 'guarded',
        family: 'udp4',
        port: 0,
        allowOutboundDestinations: true,
        destinationAllowlist: [`127.0.0.1:${target.port}`],
      },
      async (value, server) => {
        await server.reply(value, Buffer.from('a'));
        await server.reply(value, Buffer.from('b'));
        await assert.rejects(server.reply(value, Buffer.from('c')), code('EK_SOCKET_DATAGRAM'));
        checked = true;
      },
    );
    await listener.start();
    client.send(Buffer.from('ab'), listener.boundAddress!.network!.port, '127.0.0.1');
    await waitFor(() => checked);
    await listener.sendTo(
      { address: '127.0.0.1', family: 'IPv4', port: target.port },
      Buffer.from('explicit'),
    );
    await assert.rejects(
      listener.sendTo(
        {
          address: '127.0.0.1',
          family: 'IPv4',
          port: target.port === 65535 ? 65534 : target.port + 1,
        },
        Buffer.from('x'),
      ),
      code('EK_SOCKET_DATAGRAM'),
    );
    assert.equal(listener.stats().sentApplicationBytes, 10);
  } finally {
    client.close();
    await stop(application);
  }
});

test('UDP handler and queue bounds count overload and keep failing handlers local', async () => {
  const { application, service } = await app();
  const client = dgram.createSocket('udp4');
  let release = () => {},
    calls = 0;
  const gate = new Promise<void>((resolve) => {
    release = resolve;
  });
  try {
    const listener = service.createUdpServer(
      {
        name: 'queue',
        family: 'udp4',
        port: 0,
        maxConcurrentHandlers: 1,
        maxQueuedDatagrams: 1,
        maxDatagramBytes: 4,
      },
      async () => {
        calls++;
        await gate;
        throw new Error('Private source');
      },
    );
    await listener.start();
    const port = listener.boundAddress!.network!.port;
    for (let i = 0; i < 5; i++) client.send(Buffer.from('x'), port, '127.0.0.1');
    client.send(Buffer.alloc(5), port, '127.0.0.1');
    await waitFor(() => listener.stats().droppedDatagrams >= 4);
    assert.equal(calls, 1);
    release();
    await waitFor(() => calls === 2 && listener.stats().errors === 2);
    assert.equal(listener.state, 'LISTENING');
  } finally {
    release();
    client.close();
    await stop(application);
  }
});

test('Unix sockets use private permissions, preserve occupied paths and remove only their own inode', async () => {
  const directory = await mkdtemp(join(tmpdir(), 'arkenivajs-ipc-')),
    path = join(directory, 'control.sock'),
    { application, service } = await app();
  try {
    const listener = service.createUnixServer({ name: 'unix', path }, echo);
    await listener.start();
    assert.equal(Number((await lstat(path)).mode & 0o777), 0o600);
    assert.deepEqual(await exchange(listener), Buffer.from([0, 1, 2, 255]));
    await unlink(path);
    await writeFile(path, 'foreign fixture replacement', { mode: 0o600 });
    await listener.stop();
    assert.equal(await readFile(path, 'utf8'), 'foreign fixture replacement');
    const occupied = service.createUnixServer({ name: 'occupied', path }, echo);
    await assert.rejects(occupied.start(), code('EK_SOCKET_BIND'));
    assert.equal(await readFile(path, 'utf8'), 'foreign fixture replacement');
    const symlinkPath = join(directory, 'symlink.sock');
    await symlink(path, symlinkPath);
    const linked = service.createUnixServer({ name: 'linked', path: symlinkPath }, echo);
    await assert.rejects(linked.start(), code('EK_SOCKET_BIND'));
    assert.equal((await lstat(symlinkPath)).isSymbolicLink(), true);
    const normal = service.createUnixServer(
      { name: 'normal', path: join(directory, 'normal.sock') },
      echo,
    );
    await normal.start();
    await normal.stop();
    await assert.rejects(lstat(join(directory, 'normal.sock')), { code: 'ENOENT' });
  } finally {
    await stop(application);
    await rm(directory, { recursive: true, force: true });
  }
});

test(
  'Dynamic native listeners detach the registering task and preserve write backpressure admission',
  { timeout: 5000 },
  async () => {
    const { application, service } = await app(),
      request = new AsyncLocalStorage<string>();
    let detached = false,
      pending: Promise<void> | undefined,
      capacity: Promise<void> | undefined;
    try {
      const listener = await request.run('unrelated-owner-request', async () => {
        const handle = service.createTcpServer(
          { name: 'backpressure', port: 0, maxPendingWriteBytes: 1048576 },
          async (peer) => {
            detached = request.getStore() === undefined;
            pending = peer.send(Buffer.alloc(1048576, 42));
            capacity = assert.rejects(peer.send(Buffer.from('excess')), code('EK_SOCKET_CAPACITY'));
            await pending;
            await peer.end();
            peer.close();
          },
        );
        await handle.start();
        return handle;
      });
      const client = await connect(listener),
        received: Buffer[] = [];
      for await (const chunk of client) received.push(chunk);
      await pending;
      await capacity;
      assert.equal(detached, true);
      assert.equal(Buffer.concat(received).length, 1048576);
      assert.equal(listener.stats().sentApplicationBytes, 1048576);
    } finally {
      await stop(application);
    }
  },
);

test(
  'Stop cancellation destroys native streams even when a handler never settles',
  { timeout: 5000 },
  async () => {
    const { application, service } = await app();
    let peer: SocketPeer | undefined;
    try {
      const listener = service.createTcpServer({ name: 'uncooperative', port: 0 }, (value) => {
        peer = value;
        return new Promise(() => undefined);
      });
      await listener.start();
      const client = await connect(listener);
      client.on('error', () => undefined);
      const closed = once(client, 'close');
      await waitFor(() => peer !== undefined);
      await assert.rejects(listener.stop({ timeoutMs: 5 }), code('EK_TIMEOUT'));
      await closed;
      await waitFor(() => peer!.signal.aborted);
      assert.equal(listener.state, 'CLOSED');
      await listener.stop();
    } finally {
      await stop(application);
    }
  },
);

test(
  'Native IPv6 loopback retains TCP stream and UDP datagram semantics',
  { timeout: 5000 },
  async (t) => {
    const { application, service } = await app();
    const client = dgram.createSocket('udp6');
    try {
      const probe = net.createServer();
      try {
        await new Promise<void>((resolve, reject) => {
          probe.once('error', reject);
          probe.listen(0, '::1', resolve);
        });
      } catch (cause) {
        if (
          ['EADDRNOTAVAIL', 'EAFNOSUPPORT', 'ENETUNREACH'].includes(
            (cause as NodeJS.ErrnoException).code ?? '',
          )
        ) {
          t.skip('Native IPv6 loopback is unavailable; IPv6 has not been verified');
          return;
        }
        throw cause;
      } finally {
        if (probe.listening) await new Promise<void>((resolve) => probe.close(() => resolve()));
      }
      const tcp = service.createTcpServer(
          { name: 'ipv6-stream', host: '::1', port: 0, ipv6Only: true },
          echo,
        ),
        udp = service.createUdpServer(
          { name: 'ipv6-datagram', family: 'udp6', host: '::1', port: 0, ipv6Only: true },
          async (value, server) => {
            await server.reply(value, value.bytes);
          },
        );
      await tcp.start();
      await udp.start();
      assert.deepEqual(await exchange(tcp), Buffer.from([0, 1, 2, 255]));
      const response = once(client, 'message');
      client.send(Buffer.from('v6'), udp.boundAddress!.network!.port, '::1');
      assert.deepEqual((await response)[0], Buffer.from('v6'));
    } finally {
      try {
        client.close();
      } catch {
        /* An unavailable IPv6 fixture was never bound. */
      }
      await stop(application);
    }
  },
);

test(
  'UDP cancellation preserves native send acceptance without replay or excess pending writes',
  { timeout: 5000 },
  async () => {
    const { application, service } = await app(),
      client = dgram.createSocket('udp4');
    try {
      await new Promise<void>((resolve) => client.bind(0, '127.0.0.1', resolve));
      const target = client.address(),
        listener = service.createUdpServer(
          {
            name: 'sending',
            family: 'udp4',
            port: 0,
            maxConcurrentHandlers: 1,
            allowOutboundDestinations: true,
            destinationAllowlist: [`127.0.0.1:${target.port}`],
          },
          () => undefined,
        );
      await listener.start();
      const controller = new AbortController(),
        response = once(client, 'message'),
        address = { address: '127.0.0.1', port: target.port, family: 'IPv4' as const };
      const first = listener.sendTo(address, Buffer.from('once'), { signal: controller.signal });
      const exceeded = listener.sendTo(address, Buffer.from('excess'));
      controller.abort('Private abort data');
      await assert.rejects(first, code('EK_ABORTED'));
      await assert.rejects(exceeded, code('EK_SOCKET_CAPACITY'));
      assert.equal((await response)[0].toString('utf8'), 'once');
      await waitFor(() => listener.stats().sentApplicationBytes === 4);
      assert.equal(listener.stats().sentApplicationBytes, 4);
    } finally {
      client.close();
      await stop(application);
    }
  },
);

test(
  'Forced UDP shutdown closes the kernel endpoint while an application handler remains uncooperative',
  { timeout: 5000 },
  async () => {
    const { application, service } = await app(),
      client = dgram.createSocket('udp4');
    let entered = false,
      release = () => {};
    const gate = new Promise<void>((resolve) => {
      release = resolve;
    });
    try {
      const listener = service.createUdpServer(
        { name: 'forced', family: 'udp4', port: 0 },
        async () => {
          entered = true;
          await gate;
        },
      );
      await listener.start();
      const port = listener.boundAddress!.network!.port;
      client.send(Buffer.from('pending'), port, '127.0.0.1');
      await waitFor(() => entered);
      await assert.rejects(listener.stop({ timeoutMs: 5 }), code('EK_TIMEOUT'));
      assert.equal(listener.state, 'CLOSED');
      const probe = dgram.createSocket('udp4');
      try {
        await new Promise<void>((resolve, reject) => {
          probe.once('error', reject);
          probe.bind(port, '127.0.0.1', resolve);
        });
      } finally {
        probe.close();
      }
    } finally {
      release();
      client.close();
      await stop(application);
    }
  },
);

test(
  'Native stream roundtrips preserve arbitrary binary payloads across concurrent clients',
  { timeout: 5000 },
  async () => {
    const { application, service } = await app();
    try {
      const listener = service.createTcpServer(
        { name: 'binary-property', port: 0, maxConnections: 32 },
        echo,
      );
      await listener.start();
      await fc.assert(
        fc.asyncProperty(
          fc.array(fc.uint8Array({ maxLength: 1024 }), { minLength: 1, maxLength: 8 }),
          async (values) => {
            const results = await Promise.all(
              values.map((value) => exchange(listener, Buffer.from(value))),
            );
            results.forEach((value, index) => assert.deepEqual(value, Buffer.from(values[index]!)));
          },
        ),
        { numRuns: 12 },
      );
      assert.equal(listener.stats().rejectedConnections, 0);
    } finally {
      await stop(application);
    }
  },
);

test(
  'Returning an unread iterator closes its native peer and overlapping reads cannot accumulate',
  { timeout: 5000 },
  async () => {
    const { application, service } = await app();
    let calls = 0;
    try {
      const listener = service.createTcpServer(
        { name: 'iterator-lifetime', port: 0 },
        async (peer) => {
          const iterator = peer.chunks()[Symbol.asyncIterator]();
          if (++calls === 1) {
            await iterator.return!();
            return;
          }
          const pending = iterator.next();
          const rejected = assert.rejects(iterator.next(), code('EK_SOCKET_STATE'));
          const interrupted = assert.rejects(pending, code('EK_SOCKET_IO'));
          await iterator.return!();
          await rejected;
          await interrupted;
        },
      );
      await listener.start();
      for (let i = 0; i < 2; i++) {
        const client = await connect(listener);
        client.on('error', () => undefined);
        await once(client, 'close');
      }
      await waitFor(() => listener.stats().activeConnections === 0);
      assert.equal(calls, 2);
      assert.equal(listener.stats().errors, 0);
    } finally {
      await stop(application);
    }
  },
);
