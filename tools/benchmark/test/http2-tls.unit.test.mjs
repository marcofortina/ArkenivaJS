// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import assert from 'node:assert/strict';
import { test } from 'node:test';
import { createSecureServer, constants } from 'node:http2';
import { createServer as createHttpsServer } from 'node:https';
import { readFile, access, mkdtemp, rm } from 'node:fs/promises';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { join } from 'node:path';
import { createHttpTlsFixture, observeHttpsServer } from '../http-tls.mjs';
import { probeHttp2Tls, verifySecureHttp2Server } from '../http2-tls.mjs';

const body = JSON.stringify({ ok: true, value: 7, padding: 'x'.repeat(94) });

async function ownedServer(fixture, handler = (_request, reply) => reply.end(body), h2 = true) {
  const server = (h2 ? createSecureServer : createHttpsServer)({
      key: await readFile(fixture.privateKeyFile),
      cert: await readFile(fixture.certificateFile),
      minVersion: 'TLSv1.3',
      ...(h2 ? { allowHTTP1: true } : {}),
    }),
    sockets = new Set(),
    sessions = new Set(),
    streams = new Set(),
    retirements = [],
    stats = {
      acceptedConnections: 0,
      http2Requests: 0,
      http11Requests: 0,
      sessionsOpened: 0,
      sessionsClosed: 0,
      streamsOpened: 0,
      streamsClosed: 0,
      resetCodes: [],
      forcedClosures: 0,
    };
  server.on('tlsClientError', () => {});
  server.on('connection', (socket) => {
    stats.acceptedConnections++;
    sockets.add(socket);
    retirements.push(
      new Promise((resolve) =>
        socket.once('close', () => {
          sockets.delete(socket);
          resolve();
        }),
      ),
    );
  });
  if (h2) {
    server.on('sessionError', () => {});
    server.on('session', (session) => {
      stats.sessionsOpened++;
      sessions.add(session);
      session.on('error', () => {});
      retirements.push(
        new Promise((resolve) =>
          session.once('close', () => {
            stats.sessionsClosed++;
            sessions.delete(session);
            resolve();
          }),
        ),
      );
    });
    server.on('stream', (stream) => {
      stats.streamsOpened++;
      streams.add(stream);
      stream.on('error', () => {});
      retirements.push(
        new Promise((resolve) =>
          stream.once('close', () => {
            stats.streamsClosed++;
            stats.resetCodes.push(stream.rstCode);
            streams.delete(stream);
            resolve();
          }),
        ),
      );
    });
  }
  server.on('request', (request, reply) => {
    if (request.httpVersion === '2.0') stats.http2Requests++;
    else if (request.httpVersion === '1.1') stats.http11Requests++;
    else assert.fail('The owned listener received an unexpected HTTP version');
    handler(request, reply);
  });
  await new Promise((resolve, reject) => {
    server.once('error', reject);
    server.listen(0, '127.0.0.1', resolve);
  });
  let closing;
  return {
    server,
    input: {
      origin: 'https://localhost:' + server.address().port,
      certificateFile: fixture.certificateFile,
      expectedBody: body,
    },
    stats,
    close() {
      return (closing ??= (async () => {
        let timer;
        try {
          const closed = new Promise((resolve, reject) =>
            server.close((cause) => (cause ? reject(cause) : resolve())),
          );
          timer = setTimeout(() => {
            stats.forcedClosures += sockets.size + sessions.size;
            for (const session of sessions) session.destroy();
            for (const socket of sockets) socket.destroy();
          }, 1000);
          await closed;
          await Promise.all(retirements);
          assert.equal(sessions.size, 0);
          assert.equal(streams.size, 0);
          assert.equal(sockets.size, 0);
        } finally {
          clearTimeout(timer);
        }
      })());
    },
  };
}

test(
  'One secure listener negotiates real HTTP2 and HTTP1 fallback with exact trust, bytes and retired resources',
  { timeout: 10000 },
  async () => {
    const fixture = await createHttpTlsFixture();
    let owner, observer;
    try {
      owner = await ownedServer(fixture);
      observer = observeHttpsServer(owner.server, { http2: true, expectedHttpVersion: '2.0' });
      const result = await verifySecureHttp2Server(owner.input);
      await observer.waitForSessionRetirement();
      await owner.close();
      const counts = observer.snapshot();
      assert.equal(counts.http2Requests, 1);
      assert.equal(counts.http11Requests, 1);
      assert.equal(counts.unexpectedHttpVersions, 1);
      assert.equal(counts.http2SessionsOpened, 1);
      assert.equal(counts.http2SessionsClosed, 1);
      assert.equal(counts.activeHttp2Sessions, 0);
      assert.equal(counts.http2SessionErrors, 0);
      observer.reset();
      assert.equal(observer.snapshot().http2SessionsOpened, 0);
      assert.deepEqual(result.observedResponseProtocols, ['HTTP/2.0', 'HTTP/1.1']);
      assert.equal(result.http2WrongNameRejected, true);
      assert.equal(result.http2UntrustedCaRejected, true);
      for (const value of [result.http2, result.http1Fallback.positive]) {
        assert.equal(value.byteIdentityVerified, true);
        assert.equal(value.responseBytes, 128);
        assert.equal(value.tls.authorized, true);
        assert.equal(value.tls.sessionReused, false);
        assert.equal(value.tls.version, 'TLSv1.3');
        assert.match(value.tls.cipher, /^TLS_/);
        assert.equal(value.tls.certificateKeyType, 'ec');
        assert.equal(value.tls.certificateNamedCurve, 'prime256v1');
        assert.equal(value.tls.certificateKeyBits, 256);
        for (const instant of Object.values(value.timings))
          assert.ok(Number.isFinite(instant) && instant >= 0);
      }
      assert.equal(result.http2.tls.alpn, 'h2');
      assert.equal(result.http1Fallback.positive.tls.alpn, 'http/1.1');
      assert.equal(result.http2.streamClosed, true);
      assert.equal(result.http2.sessionClosed, true);
      assert.equal(result.http2.tlsSocketClosed, true);
      assert.equal(result.http1Fallback.positive.physicalClientClosed, true);
      assert.equal(owner.stats.acceptedConnections, 6);
      assert.equal(owner.stats.http2Requests, 1);
      assert.equal(owner.stats.http11Requests, 1);
      assert.equal(owner.stats.sessionsOpened, 1);
      assert.equal(owner.stats.sessionsClosed, 1);
      assert.equal(owner.stats.streamsOpened, 1);
      assert.equal(owner.stats.streamsClosed, 1);
      assert.equal(owner.stats.forcedClosures, 0);
      assert.doesNotMatch(
        JSON.stringify(result),
        /localhost|127\.0\.0\.1|wrong\.invalid|server\.pem|server\.key|CERTIFICATE/,
      );
    } finally {
      observer?.close();
      try {
        await owner?.close();
      } finally {
        await fixture.close();
        await assert.rejects(access(fixture.privateKeyFile), { code: 'ENOENT' });
      }
    }
  },
);

test(
  'HTTP2 body corruption and overflow fail closed before a fresh healthy stream succeeds',
  { timeout: 10000 },
  async () => {
    const fixture = await createHttpTlsFixture();
    let owner,
      mode = 'corrupted';
    try {
      owner = await ownedServer(fixture, (_request, reply) =>
        reply.end(
          mode === 'corrupted' ? 'z'.repeat(128) : mode === 'oversized' ? body + 'x' : body,
        ),
      );
      await assert.rejects(probeHttp2Tls(owner.input), { message: 'The owned HTTP2 probe failed' });
      mode = 'oversized';
      await assert.rejects(probeHttp2Tls(owner.input), { message: 'The owned HTTP2 probe failed' });
      mode = 'healthy';
      const result = await probeHttp2Tls(owner.input);
      assert.equal(result.byteIdentityVerified, true);
      assert.equal(result.streamClosed, true);
      assert.equal(result.sessionClosed, true);
      assert.equal(result.tlsSocketClosed, true);
      await owner.close();
      assert.equal(owner.stats.http2Requests, 3);
      assert.equal(owner.stats.sessionsOpened, 3);
      assert.equal(owner.stats.sessionsClosed, 3);
      assert.equal(owner.stats.streamsOpened, 3);
      assert.equal(owner.stats.streamsClosed, 3);
      assert.equal(owner.stats.forcedClosures, 0);
    } finally {
      try {
        await owner?.close();
      } finally {
        await fixture.close();
      }
    }
  },
);

test('Secure HTTP2 and HTTP1 fallback smoke refuse unmarked execution before creating PKI or reports', async () => {
  const directory = await mkdtemp('/tmp/arkenivajs-http2-entry-');
  try {
    for (const selector of ['--smoke-http2', '--smoke-http1-fallback']) {
      const output = join(directory, selector.slice(2)),
        result = spawnSync(
          process.execPath,
          [fileURLToPath(new URL('../http.mjs', import.meta.url)), output, selector],
          { env: { PATH: process.env.PATH }, encoding: 'utf8', timeout: 10000 },
        );
      assert.equal(result.error, undefined);
      assert.equal(result.status, 1);
      assert.equal(result.stdout, '');
      assert.equal(
        result.stderr,
        'The HTTP benchmark failed; inspect the protected external artifacts\n',
      );
      await assert.rejects(access(output), { code: 'ENOENT' });
    }
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});

test(
  'An active HTTP2 abort sends native cancellation and retires its stream/session without leaking the supplied reason',
  { timeout: 10000 },
  async () => {
    const fixture = await createHttpTlsFixture(),
      controller = new AbortController();
    let owner, received;
    const requestSeen = new Promise((resolve) => {
      received = resolve;
    });
    try {
      owner = await ownedServer(fixture, () => received());
      const running = probeHttp2Tls({ ...owner.input, signal: controller.signal });
      const checked = assert.rejects(running, (cause) => {
        assert.equal(cause.code, 'ABORT_ERR');
        assert.equal(cause.message, 'The owned HTTP2 probe failed');
        assert.equal(cause.cause, undefined);
        assert.doesNotMatch(String(cause), /private cancellation detail/);
        return true;
      });
      await requestSeen;
      controller.abort(new Error('private cancellation detail'));
      await checked;
      const alreadyAborted = new AbortController();
      alreadyAborted.abort(new Error('private cancellation detail'));
      await assert.rejects(
        probeHttp2Tls({
          ...owner.input,
          certificateFile: '/unread-certificate',
          signal: alreadyAborted.signal,
        }),
        { code: 'ABORT_ERR' },
      );
      await owner.close();
      assert.equal(owner.stats.acceptedConnections, 1);
      assert.equal(owner.stats.http2Requests, 1);
      assert.equal(owner.stats.sessionsOpened, 1);
      assert.equal(owner.stats.sessionsClosed, 1);
      assert.equal(owner.stats.streamsClosed, 1);
      assert.deepEqual(owner.stats.resetCodes, [constants.NGHTTP2_CANCEL]);
      assert.equal(owner.stats.forcedClosures, 0);
    } finally {
      controller.abort();
      try {
        await owner?.close();
      } finally {
        await fixture.close();
      }
    }
  },
);

test(
  'An HTTP1-only peer cannot silently satisfy the HTTP2 control and foreign origins are rejected before I/O',
  { timeout: 10000 },
  async () => {
    const fixture = await createHttpTlsFixture();
    let owner;
    try {
      owner = await ownedServer(fixture, undefined, false);
      await assert.rejects(probeHttp2Tls(owner.input), { message: 'The owned HTTP2 probe failed' });
      await assert.rejects(
        probeHttp2Tls({
          ...owner.input,
          origin: 'https://private-user:private-origin-value@foreign.invalid:443',
          certificateFile: '/unread-certificate',
        }),
        (cause) => {
          assert.equal(cause.message, 'The owned HTTP2 probe failed');
          assert.equal(cause.cause, undefined);
          assert.doesNotMatch(String(cause), /private-user|private-origin-value|foreign\.invalid/);
          return true;
        },
      );
      await owner.close();
      assert.equal(owner.stats.acceptedConnections, 1);
      assert.equal(owner.stats.http11Requests, 0);
      assert.equal(owner.stats.http2Requests, 0);
      assert.equal(owner.stats.forcedClosures, 0);
    } finally {
      try {
        await owner?.close();
      } finally {
        await fixture.close();
      }
    }
  },
);
