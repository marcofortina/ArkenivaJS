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
import { setTimeout as delay } from 'node:timers/promises';
import { mailPrivateValues, attachmentBytes, mailReceiptDigest } from './mail-workload.mjs';

/** Only this ephemeral nonforwarding SMTP server receives the controlled comparison messages. */
export async function startMailFixture() {
  const directory = await mkdtemp(join(tmpdir(), 'arkenivajs-mail-comparison-')),
    trustAnchorFile = join(directory, 'server.pem'),
    keyFile = join(directory, 'server.key'),
    credential = randomBytes(24).toString('base64url'),
    state = {
      acceptedMessages: 0,
      attachmentBytes: 0,
      authentications: 0,
      secureSessions: 0,
      envelopeRecipients: 0,
      mimeRecipients: 0,
      observedMimeBytes: 0,
      activeMessages: 0,
      peakActiveMessages: 0,
      failedMessages: 0,
      activeConnections: 0,
      peakConnections: 0,
      connectionsOpened: 0,
      connectionsClosed: 0,
    },
    connections = new Set(),
    ids = [],
    seen = new Set(),
    tasks = new Set();
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
      maxClients: 4,
      maxRecipients: 1,
      size: 65536,
      disableReverseLookup: true,
      onConnect(session, done) {
        connections.add(session.id);
        state.connectionsOpened++;
        state.activeConnections = connections.size;
        state.peakConnections = Math.max(state.peakConnections, connections.size);
        done();
      },
      onClose(session, done) {
        if (connections.delete(session.id)) state.connectionsClosed++;
        state.activeConnections = connections.size;
        done();
      },
      onMailFrom(address, session, done) {
        if (
          !session.secure ||
          session.user !== 'owned-user' ||
          address.address !== mailPrivateValues[1]
        )
          return done(new Error('The owned SMTP sender was rejected'));
        done();
      },
      onRcptTo(address, session, done) {
        if (
          !session.secure ||
          session.user !== 'owned-user' ||
          address.address !== mailPrivateValues[2]
        )
          return done(new Error('The owned SMTP recipient was rejected'));
        state.envelopeRecipients++;
        done();
      },
      onAuth(auth, session, done) {
        if (!session.secure || auth.username !== 'owned-user' || auth.password !== credential)
          return done(new Error('The owned SMTP authentication was rejected'));
        state.authentications++;
        state.secureSessions++;
        done(null, { user: 'owned-user' });
      },
      onData(stream, session, done) {
        const chunks = [];
        let total = 0,
          finished = false;
        state.activeMessages++;
        state.peakActiveMessages = Math.max(state.peakActiveMessages, state.activeMessages);
        const finish = (error) => {
          if (finished) return;
          finished = true;
          state.activeMessages--;
          if (error) state.failedMessages++;
          done(error, error ? undefined : 'Owned fixture accepted');
        };
        stream.once('error', () => finish(new Error('The owned SMTP source failed')));
        if (state.activeMessages > 4) {
          stream.destroy(new Error('The owned SMTP parser capacity was exceeded'));
          finish(new Error('The owned SMTP parser capacity was exceeded'));
          return;
        }
        stream.on('data', (chunk) => {
          total += chunk.length;
          if (total > 65536)
            stream.destroy(new Error('The owned SMTP fixture capacity was exceeded'));
          else chunks.push(chunk);
        });
        stream.once('end', () => {
          const task = (async () => {
            const message = await simpleParser(Buffer.concat(chunks));
            assert.equal(finished, false);
            assert.equal(session.secure, true);
            assert.equal(session.user, 'owned-user');
            assert.equal(session.envelope.mailFrom.address, mailPrivateValues[1]);
            assert.deepEqual(
              session.envelope.rcptTo.map((value) => value.address),
              [mailPrivateValues[2]],
            );
            assert.deepEqual(
              message.from.value.map((value) => value.address),
              [mailPrivateValues[1]],
            );
            assert.deepEqual(
              message.to.value.map((value) => value.address),
              [mailPrivateValues[2]],
            );
            assert.equal(message.cc, undefined);
            assert.equal(message.bcc, undefined);
            assert.equal(message.subject, 'Owned SMTP comparison');
            assert.equal(
              message.text.replace(/\r\n/g, '\n').replace(/\n$/, ''),
              mailPrivateValues[0],
            );
            assert.equal(message.attachments.length, 1);
            assert.equal(message.attachments[0].filename, mailPrivateValues[3]);
            assert.deepEqual(message.attachments[0].content, attachmentBytes);
            assert.equal(typeof message.messageId, 'string');
            assert.ok(message.messageId.length > 0 && message.messageId.length <= 2048);
            assert.ok(ids.length < 512 && !seen.has(message.messageId));
            seen.add(message.messageId);
            ids.push(message.messageId);
            state.observedMimeBytes += total;
            state.mimeRecipients++;
            state.attachmentBytes += message.attachments[0].content.length;
            state.acceptedMessages++;
            chunks.length = 0;
            finish();
          })().catch(() => finish(new Error('The owned MIME verification failed')));
          tasks.add(task);
          void task.finally(() => tasks.delete(task));
        });
      },
    });
    server.on('error', () => undefined);
    await new Promise((done, reject) => {
      server.once('error', reject);
      server.listen(0, '127.0.0.1', done);
    });
    const port = server.server.address().port;
    const quiescent = async () => {
      for (let attempt = 0; attempt < 500; attempt++) {
        if (state.activeConnections === 0 && state.activeMessages === 0 && tasks.size === 0) return;
        await delay(10);
      }
      throw new Error('The owned SMTP physical resources did not retire');
    };
    return {
      fixture: { port, credential },
      trustAnchorFile,
      state,
      quiescent,
      verifyReceipts(profiles) {
        let offset = 0;
        for (const profile of profiles) {
          assert.ok(Number.isSafeInteger(profile.totalReceipts) && profile.totalReceipts >= 0);
          const next = offset + profile.totalReceipts;
          assert.ok(next <= ids.length);
          assert.equal(mailReceiptDigest(ids.slice(offset, next)), profile.receiptDigest);
          offset = next;
        }
        assert.equal(offset, ids.length);
        assert.equal(offset, state.acceptedMessages);
      },
      async close() {
        try {
          await new Promise((done) => server.close(done));
          await Promise.allSettled([...tasks]);
          await quiescent();
        } finally {
          ids.length = 0;
          seen.clear();
          key.fill(0);
          await rm(directory, { recursive: true, force: true });
        }
      },
    };
  } catch (error) {
    if (server?.server.listening) await new Promise((done) => server.close(done));
    key?.fill(0);
    await rm(directory, { recursive: true, force: true });
    throw error;
  }
}
