// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import assert from 'node:assert/strict';
import { before, after, test } from 'node:test';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { X509Certificate, createPrivateKey } from 'node:crypto';
import { mkdtemp, chmod, readFile, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import net from 'node:net';
import tls from 'node:tls';
import { once } from 'node:events';
import { setTimeout as delay } from 'node:timers/promises';
import { createApplication, KitError } from '@arkenivajs/core';
import { socketPlugin, SOCKET_CAPABILITY } from '../../dist/index.js';
import type { SocketService, SocketPeer, SocketServerHandle } from '../../dist/index.js';

const execute = promisify(execFile);
let directory: string;
const files = () => ({
  certificateFile: join(directory, 'server.pem'),
  privateKeyFile: join(directory, 'server.key'),
});
const code = (value: string) => (cause: unknown) =>
  cause instanceof KitError && cause.code === value;
const echo = async (peer: SocketPeer) => {
  for await (const chunk of peer.chunks()) await peer.send(chunk);
  await peer.end();
};
before(async () => {
  directory = await mkdtemp(join(tmpdir(), 'arkenivajs-socket-tls-'));
  await chmod(directory, 0o700);
  for (const name of ['server', 'untrusted']) {
    await execute(
      'openssl',
      [
        'req',
        '-x509',
        '-newkey',
        'ec',
        '-pkeyopt',
        'ec_paramgen_curve:P-256',
        '-nodes',
        '-days',
        '1',
        '-subj',
        '/CN=localhost',
        '-addext',
        'subjectAltName=DNS:localhost,IP:127.0.0.1',
        '-keyout',
        join(directory, name + '.key'),
        '-out',
        join(directory, name + '.pem'),
      ],
      { timeout: 10000 },
    );
    await chmod(join(directory, name + '.key'), 0o600);
  }
  await Promise.all([
    writeFile(join(directory, 'expired.index'), '', { mode: 0o600 }),
    writeFile(join(directory, 'expired.serial'), '01\n', { mode: 0o600 }),
    writeFile(
      join(directory, 'expired.cnf'),
      '[ca]\ndefault_ca=fixture\n[fixture]\ndatabase=expired.index\n' +
        'new_certs_dir=.\nserial=expired.serial\ncertificate=server.pem\n' +
        'private_key=server.key\ndefault_md=sha256\npolicy=subject\n' +
        'x509_extensions=leaf\n[subject]\ncommonName=supplied\n[leaf]\n' +
        'basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature\n' +
        'extendedKeyUsage=serverAuth,clientAuth\nsubjectAltName=DNS:localhost,IP:127.0.0.1\n',
      { mode: 0o600 },
    ),
  ]);
  const options = { cwd: directory, timeout: 10000 };
  await execute(
    'openssl',
    ['req', '-new', '-key', 'server.key', '-subj', '/CN=localhost', '-out', 'expired.csr'],
    options,
  );
  await execute(
    'openssl',
    [
      'ca',
      '-batch',
      '-selfsign',
      '-notext',
      '-config',
      'expired.cnf',
      '-in',
      'expired.csr',
      '-startdate',
      '20200101000000Z',
      '-enddate',
      '20200102000000Z',
      '-out',
      'expired.pem',
    ],
    options,
  );
  const expired = new X509Certificate(await readFile(join(directory, 'expired.pem')));
  assert.equal(Date.parse(expired.validFrom), Date.UTC(2020, 0, 1));
  assert.equal(Date.parse(expired.validTo), Date.UTC(2020, 0, 2));
  assert.ok(Date.parse(expired.validFrom) < Date.parse(expired.validTo));
  assert.ok(Date.parse(expired.validTo) < Date.now());
  assert.equal(expired.checkHost('localhost'), 'localhost');
  assert.equal(expired.checkIP('127.0.0.1'), '127.0.0.1');
  assert.equal(
    expired.checkPrivateKey(createPrivateKey(await readFile(files().privateKeyFile))),
    true,
  );
});
after(async () => {
  await rm(directory, { recursive: true, force: true });
});
async function fixture() {
  const app = await createApplication({
    service: { name: 'tls-socket', version: '1.0.0', environment: 'test' },
    plugins: [socketPlugin()],
  });
  await app.start();
  return { app, service: app.resolve<SocketService>(SOCKET_CAPABILITY) };
}
async function exchange(listener: SocketServerHandle, options: tls.ConnectionOptions = {}) {
  const socket = tls.connect({
    host: '127.0.0.1',
    port: listener.boundAddress!.network!.port,
    servername: 'localhost',
    ca: await readFile(files().certificateFile),
    ...options,
  });
  const completed = new Promise<Buffer>((resolve, reject) => {
    const chunks: Buffer[] = [];
    socket.on('data', (bytes) => chunks.push(bytes));
    socket.once('error', reject);
    socket.once('end', () => {
      const bytes = Buffer.concat(chunks);
      if (bytes.length) resolve(bytes);
      else reject(new Error('The secure fixture did not accept application data'));
    });
    socket.once('secureConnect', () => socket.end(Buffer.from('verified')));
  });
  try {
    return await completed;
  } finally {
    socket.destroy();
  }
}
test(
  'Native TLS completes a verified handshake before invoking a byte-stream handler',
  { timeout: 5000 },
  async () => {
    const { app, service } = await fixture();
    let calls = 0;
    try {
      const listener = service.createTlsServer(
        { name: 'secure', port: 0, tls: files() },
        async (peer) => {
          calls++;
          await echo(peer);
        },
      );
      await listener.start();
      assert.deepEqual(await exchange(listener), Buffer.from('verified'));
      assert.equal(calls, 1);
      await assert.rejects(
        exchange(listener, { ca: await readFile(join(directory, 'untrusted.pem')) }),
      );
      assert.equal(calls, 1);
    } finally {
      await app.stop({ timeoutMs: 1000 });
    }
  },
);
test(
  'Required client trust and minimum TLS policy cannot be bypassed by an untrusted connection',
  { timeout: 5000 },
  async () => {
    const { app, service } = await fixture();
    let calls = 0;
    try {
      const listener = service.createTlsServer(
        {
          name: 'mutual',
          port: 0,
          tls: {
            ...files(),
            caFile: files().certificateFile,
            clientCertificate: 'required',
            minVersion: 'TLSv1.3',
          },
        },
        async (peer) => {
          calls++;
          await echo(peer);
        },
      );
      await listener.start();
      await assert.rejects(exchange(listener));
      await assert.rejects(
        exchange(listener, {
          cert: await readFile(join(directory, 'untrusted.pem')),
          key: await readFile(join(directory, 'untrusted.key')),
        }),
      );
      await assert.rejects(exchange(listener, { maxVersion: 'TLSv1.2' }));
      assert.equal(calls, 0);
      assert.deepEqual(
        await exchange(listener, {
          cert: await readFile(files().certificateFile),
          key: await readFile(files().privateKeyFile),
        }),
        Buffer.from('verified'),
      );
      assert.equal(calls, 1);
    } finally {
      await app.stop({ timeoutMs: 1000 });
    }
  },
);
test(
  'Invalid, expired, unavailable and mismatched TLS material never binds a listener',
  { timeout: 5000 },
  async () => {
    const { app, service } = await fixture();
    try {
      for (const [index, material] of [
        { ...files(), privateKeyFile: join(directory, 'missing.key') },
        { ...files(), privateKeyFile: join(directory, 'untrusted.key') },
        { ...files(), certificateFile: join(directory, 'expired.pem') },
      ].entries()) {
        const listener = service.createTlsServer(
          { name: 'invalid-' + index, port: 0, tls: material },
          echo,
        );
        await assert.rejects(listener.start(), code('EK_SOCKET_TLS_HANDSHAKE'));
        assert.equal(listener.state, 'FAILED');
        assert.equal(listener.boundAddress, undefined);
      }
    } finally {
      await app.stop({ timeoutMs: 1000 });
    }
  },
);
test(
  'Incomplete handshakes occupy bounded admission and expire without reaching the handler',
  { timeout: 5000 },
  async () => {
    const { app, service } = await fixture();
    let calls = 0;
    try {
      const listener = service.createTlsServer(
        { name: 'handshake', port: 0, tls: files(), maxConnections: 1, handshakeTimeoutMs: 30 },
        () => {
          calls++;
        },
      );
      await listener.start();
      const first = net.connect(listener.boundAddress!.network!.port, '127.0.0.1');
      first.on('error', () => undefined);
      await once(first, 'connect');
      const second = net.connect(listener.boundAddress!.network!.port, '127.0.0.1');
      second.on('error', () => undefined);
      await once(second, 'close');
      assert.equal(listener.stats().rejectedConnections, 1);
      await once(first, 'close');
      await delay(0);
      assert.equal(calls, 0);
      assert.ok(listener.stats().errors >= 1);
    } finally {
      await app.stop({ timeoutMs: 1000 });
    }
  },
);
