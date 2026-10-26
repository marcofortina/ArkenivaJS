// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { execFile, fork } from 'node:child_process';
import { promisify } from 'node:util';
import { mkdtemp, chmod, readFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { setTimeout as delay } from 'node:timers/promises';
import { SMTPServer } from 'smtp-server';
import { simpleParser } from 'mailparser';

const execute = promisify(execFile);
let directory: string, certificate: Buffer, key: Buffer;
before(async () => {
  directory = await mkdtemp(join(tmpdir(), 'arkenivajs-mail-tls-'));
  await chmod(directory, 0o700);
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
      'subjectAltName=DNS:localhost',
      '-keyout',
      join(directory, 'server.key'),
      '-out',
      join(directory, 'server.pem'),
    ],
    { timeout: 10000 },
  );
  await chmod(join(directory, 'server.key'), 0o600);
  [certificate, key] = await Promise.all([
    readFile(join(directory, 'server.pem')),
    readFile(join(directory, 'server.key')),
  ]);
});
after(async () => {
  key?.fill(0);
  if (directory) await rm(directory, { recursive: true, force: true });
});
async function fixture(mode = 'normal') {
  const state = { connections: 0, auth: 0, data: [] as Buffer[], secure: [] as boolean[] };
  let notify: (() => void) | undefined;
  const server = new SMTPServer({
    key,
    cert: certificate,
    logger: false,
    secure: false,
    closeTimeout: 100,
    disableReverseLookup: true,
    ...(mode === 'no-starttls' ? { disabledCommands: ['STARTTLS'] } : {}),
    onConnect(_session, done) {
      state.connections++;
      done();
    },
    onAuth(auth, session, done) {
      state.auth++;
      state.secure.push(session.secure);
      if (
        auth.username !== 'fixture-user' ||
        !['fixture-password', 'fixture-password-next'].includes(auth.password ?? '') ||
        !session.secure
      ) {
        done(new Error('The disposable SMTP authentication was rejected'));
        return;
      }
      done(null, { user: 'fixture-user' });
    },
    onRcptTo(address, _session, done) {
      if (address.address === 'reject@example.test') {
        const error = Object.assign(new Error('The disposable recipient was rejected'), {
          responseCode: 550,
        });
        done(error);
      } else done();
    },
    onData(stream, session, done) {
      const chunks: Buffer[] = [];
      let total = 0;
      stream.on('data', (bytes: Buffer) => {
        total += bytes.byteLength;
        if (total > 1048576) stream.destroy(new Error('The disposable message limit was exceeded'));
        else chunks.push(bytes);
      });
      stream.on('error', () => undefined);
      stream.on('end', () => {
        state.data.push(Buffer.concat(chunks));
        if (mode === 'hold-first' && session.envelope.rcptTo[0]?.address === 'first@example.test') {
          notify?.();
          return;
        }
        if (mode === 'lost-ack') {
          for (const connection of server.connections)
            if (connection.session.id === session.id) connection.close();
        } else if (mode !== 'hold-ack') done(null, 'Fixture accepted');
      });
    },
  });
  server.on('error', () => undefined);
  await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
  const bound = server.server.address();
  assert.ok(bound && typeof bound === 'object');
  return {
    state,
    async client(mode: string, trusted = true, timeoutMs?: number) {
      const result = await execute(
        process.execPath,
        [
          fileURLToPath(new URL('./client.js', import.meta.url)),
          JSON.stringify({ port: bound.port, mode, timeoutMs }),
        ],
        {
          timeout: 10000,
          env: {
            LANG: 'C.UTF-8',
            TZ: 'UTC',
            ...(process.env.NODE_V8_COVERAGE
              ? { NODE_V8_COVERAGE: process.env.NODE_V8_COVERAGE }
              : {}),
            ARKENIVA_MAIL_DISPOSABLE: '1',
            ...(trusted ? { NODE_EXTRA_CA_CERTS: join(directory, 'server.pem') } : {}),
          },
        },
      );
      assert.equal(result.stderr, '');
      return JSON.parse(result.stdout) as Record<string, unknown>;
    },
    async close() {
      await new Promise<void>((resolve) => server.close(resolve));
    },
    async concurrent() {
      const child = fork(
        fileURLToPath(new URL('./client.js', import.meta.url)),
        [JSON.stringify({ port: bound.port, mode: 'concurrent' })],
        {
          execPath: process.execPath,
          execArgv: [],
          stdio: ['ignore', 'pipe', 'pipe', 'ipc'],
          env: {
            LANG: 'C.UTF-8',
            TZ: 'UTC',
            ...(process.env.NODE_V8_COVERAGE
              ? { NODE_V8_COVERAGE: process.env.NODE_V8_COVERAGE }
              : {}),
            ARKENIVA_MAIL_DISPOSABLE: '1',
            NODE_EXTRA_CA_CERTS: join(directory, 'server.pem'),
          },
        },
      );
      notify = () => {
        if (child.connected) child.send({ abort: true }, () => undefined);
      };
      let output = '',
        errors = '';
      child.stdout!.on('data', (bytes: Buffer) => {
        output += bytes.toString('utf8');
      });
      child.stderr!.on('data', (bytes: Buffer) => {
        errors += bytes.toString('utf8');
      });
      const timer = setTimeout(() => child.kill('SIGKILL'), 10000);
      try {
        await new Promise<void>((resolve, reject) => {
          child.once('error', reject);
          child.once('close', (code) => {
            if (code !== 0) reject(new Error('The disposable concurrent SMTP client failed'));
            else resolve();
          });
        });
        assert.equal(errors, '');
        assert.ok(output.length < 16384);
        return JSON.parse(output) as Record<string, unknown>;
      } finally {
        clearTimeout(timer);
        notify = undefined;
      }
    },
  };
}
test('Actual STARTTLS, authentication, native MIME and pooled connection reuse preserve bounded attachments', async () => {
  const local = await fixture();
  try {
    assert.deepEqual(await local.client('two'), {
      outcome: 'accepted',
      accepted: 1,
      rejected: 0,
      transportId: true,
    });
    assert.equal(local.state.connections, 1);
    assert.equal(local.state.auth, 1);
    assert.deepEqual(local.state.secure, [true]);
    assert.equal(local.state.data.length, 2);
    const parsed = await simpleParser(local.state.data[0]!);
    assert.equal(parsed.subject, 'Native fixture 東京');
    assert.equal(parsed.from?.value[0]?.name, 'Caffè 🦊');
    assert.deepEqual(parsed.attachments[0]?.content, Buffer.from([0, 1, 2, 253, 254, 255]));
    assert.equal(parsed.attachments[0]?.filename, 'report-東京.bin');
    assert.ok(
      typeof parsed.html === 'string' &&
        !parsed.html.includes('<script') &&
        !parsed.html.includes('file:///etc/passwd'),
    );
  } finally {
    await local.close();
  }
});
test('Native verification requires trusted TLS and never leaks SMTP authentication into cleartext', async () => {
  const local = await fixture();
  try {
    assert.equal((await local.client('verify')).available, true);
    assert.equal((await local.client('verify', false)).available, false);
    assert.equal(local.state.auth, 1);
    assert.equal(local.state.data.length, 0);
  } finally {
    await local.close();
  }
  const plain = await fixture('no-starttls');
  try {
    assert.equal((await plain.client('verify')).available, false);
    assert.equal(plain.state.auth, 0);
    assert.equal(plain.state.data.length, 0);
  } finally {
    await plain.close();
  }
});
test('Actual SMTP recipient outcomes distinguish partial and total rejection and omit Bcc headers', async () => {
  const local = await fixture();
  try {
    assert.deepEqual(await local.client('partial'), {
      outcome: 'partial',
      accepted: 2,
      rejected: 1,
      transportId: true,
    });
    assert.deepEqual(await local.client('all-rejected'), {
      outcome: 'rejected',
      accepted: 0,
      rejected: 1,
      transportId: false,
    });
    assert.equal(local.state.data.length, 1);
    const parsed = await simpleParser(local.state.data[0]!);
    assert.ok(!parsed.headers.has('bcc'));
  } finally {
    await local.close();
  }
});
test('Allowlisted templates escape hostile values before the real MIME parser sees the HTML', async () => {
  const local = await fixture();
  try {
    assert.equal((await local.client('template')).outcome, 'accepted');
    const parsed = await simpleParser(local.state.data[0]!);
    assert.ok(
      typeof parsed.html === 'string' &&
        parsed.html.includes('&lt;script&gt;private-template-value&lt;'),
    );
    assert.ok(typeof parsed.html === 'string' && !parsed.html.includes('<script>'));
  } finally {
    await local.close();
  }
});
test('Credential rotation replaces the authenticated pool and a provider outage cannot reuse a warm session', async () => {
  const rotated = await fixture();
  try {
    assert.equal((await rotated.client('rotation')).outcome, 'accepted');
    assert.equal(rotated.state.connections, 2);
    assert.equal(rotated.state.auth, 2);
    assert.equal(rotated.state.data.length, 2);
  } finally {
    await rotated.close();
  }
  const unavailable = await fixture();
  try {
    assert.equal((await unavailable.client('outage')).code, 'EK_MAIL_SEND');
    assert.equal(unavailable.state.connections, 1);
    assert.equal(unavailable.state.auth, 1);
    assert.equal(unavailable.state.data.length, 1);
  } finally {
    await unavailable.close();
  }
});
test('A lost post-DATA acknowledgement is explicitly uncertain and never retried by the native pool', async () => {
  const local = await fixture('lost-ack');
  try {
    assert.deepEqual(await local.client('send'), { code: 'EK_MAIL_SEND', outcome: 'unknown' });
    await delay(100);
    assert.equal(local.state.data.length, 1);
  } finally {
    await local.close();
  }
});
test('A DATA deadline closes the owned TLS connection without retrying the submitted message', async () => {
  const local = await fixture('hold-ack');
  try {
    assert.deepEqual(await local.client('send', true, 2000), {
      code: 'EK_TIMEOUT',
      outcome: 'unknown',
    });
    await delay(100);
    assert.equal(local.state.data.length, 1);
  } finally {
    await local.close();
  }
});
test('Aborting one admitted send preserves the other pool lane and saturation has no hidden queue', async () => {
  const local = await fixture('hold-first');
  try {
    assert.deepEqual(await local.concurrent(), {
      first: 'EK_ABORTED',
      second: 'accepted',
      capacity: 'EK_MAIL_SEND',
    });
    assert.equal(local.state.data.length, 2);
    assert.equal(local.state.connections, 2);
    assert.equal(local.state.auth, 2);
  } finally {
    await local.close();
  }
});
