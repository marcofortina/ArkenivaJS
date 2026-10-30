// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { mkdtemp, readFile, chmod, rm } from 'node:fs/promises';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { SMTPServer } from 'smtp-server';
import { simpleParser } from 'mailparser';

/** Only this ephemeral nonforwarding SMTP server receives the controlled comparison messages. */
export async function startMailFixture() {
  const directory = await mkdtemp(join(tmpdir(), 'arkenivajs-mail-comparison-')),
    trustAnchorFile = join(directory, 'server.pem'),
    keyFile = join(directory, 'server.key'),
    credential = randomBytes(24).toString('base64url'),
    state = { acceptedMessages: 0, attachmentBytes: 0, authentications: 0, secureSessions: 0 };
  let server, key;
  try {
    await chmod(directory, 0o700);
    await promisify(execFile)(
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
        keyFile,
        '-out',
        trustAnchorFile,
      ],
      { timeout: 10000, maxBuffer: 65536 },
    );
    await chmod(keyFile, 0o600);
    key = await readFile(keyFile);
    server = new SMTPServer({
      key,
      cert: await readFile(trustAnchorFile),
      secure: false,
      logger: false,
      closeTimeout: 100,
      disableReverseLookup: true,
      onAuth(auth, session, done) {
        if (!session.secure || auth.username !== 'owned-user' || auth.password !== credential)
          return done(new Error('The owned SMTP authentication was rejected'));
        state.authentications++;
        state.secureSessions++;
        done(null, { user: 'owned-user' });
      },
      onData(stream, _session, done) {
        const chunks = [];
        let total = 0;
        stream.on('data', (chunk) => {
          total += chunk.length;
          if (total > 65536)
            stream.destroy(new Error('The owned SMTP fixture capacity was exceeded'));
          else chunks.push(chunk);
        });
        stream.once('error', () => done(new Error('The owned SMTP source failed')));
        stream.once('end', () => {
          void (async () => {
            const message = await simpleParser(Buffer.concat(chunks));
            assert.equal(message.subject, 'Owned SMTP comparison');
            assert.equal(message.text.trim(), 'owned-private-mail-content');
            assert.equal(message.attachments.length, 1);
            assert.equal(message.attachments[0].filename, 'owned-report.bin');
            assert.deepEqual(message.attachments[0].content, Buffer.from([0, 1, 2, 253, 254, 255]));
            state.attachmentBytes += message.attachments[0].content.length;
            state.acceptedMessages++;
            done(null, 'Owned fixture accepted');
          })().catch(() => done(new Error('The owned MIME verification failed')));
        });
      },
    });
    server.on('error', () => undefined);
    await new Promise((done, reject) => {
      server.once('error', reject);
      server.listen(0, '127.0.0.1', done);
    });
    const port = server.server.address().port;
    return {
      fixture: { port, credential },
      trustAnchorFile,
      state,
      async close() {
        await new Promise((done) => server.close(done));
        key.fill(0);
        await rm(directory, { recursive: true, force: true });
      },
    };
  } catch (error) {
    if (server?.server.listening) await new Promise((done) => server.close(done));
    key?.fill(0);
    await rm(directory, { recursive: true, force: true });
    throw error;
  }
}
