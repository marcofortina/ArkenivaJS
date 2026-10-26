// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { mkdtemp, chmod, readFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { pathToFileURL, fileURLToPath } from 'node:url';
import { createServer } from 'node:http';
import { Writable } from 'node:stream';
import { SMTPServer } from 'smtp-server';
import { simpleParser } from 'mailparser';
import { createApplication } from '@arkenivajs/core';
import { mailPlugin, MAIL_CAPABILITY } from '@arkenivajs/mail';
import type { MailService } from '@arkenivajs/mail';
import { loggingPlugin } from '@arkenivajs/logging';
import { telemetryPlugin } from '@arkenivajs/telemetry';

const execute = promisify(execFile);
async function client(port: number, metricsPort: number) {
  if (process.env.ARKENIVA_MAIL_DISPOSABLE !== '1')
    throw new Error('The mail client requires the owned disposable SMTP fixture');
  const logs: string[] = [],
    destination = new Writable({
      write(chunk: Buffer, _encoding, done) {
        logs.push(chunk.toString('utf8'));
        done();
      },
    }),
    app = await createApplication({
      service: { name: 'mail-example', version: '0.1.0', environment: 'test' },
      logging: { level: 'debug' },
      telemetry: { mode: 'standard', samplingRatio: 1 },
      plugins: [
        mailPlugin({
          transports: [
            {
              name: 'local',
              host: 'localhost',
              port,
              requireTls: true,
              usernameRef: 'mail-user',
              passwordRef: 'mail-pass',
              allowedFromAddresses: ['sender@example.test'],
              maxAttachmentBytes: 65536,
            },
          ],
          secretProvider: {
            async get(reference) {
              return { bytes: Buffer.from(reference), keyVersion: 'one' };
            },
          },
          policy: {
            maxConcurrent: 1,
            timeoutMs: 5000,
            maxInputBytes: 65536,
            maxOutputBytes: 65536,
          },
        }),
        loggingPlugin({ destination }),
        telemetryPlugin({
          endpoint: 'http://127.0.0.1:' + metricsPort,
          allowInsecureLoopback: true,
          exportIntervalMs: 1000,
          exportTimeoutMs: 1000,
        }),
      ],
    });
  try {
    await app.start();
    const mail = app.resolve<MailService>(MAIL_CAPABILITY),
      health = await mail.verifyTransport(),
      receipt = await mail.send({
        from: { address: 'sender@example.test' },
        to: [{ address: 'recipient@example.test' }],
        subject: 'Public SMTP fixture',
        text: 'private-mail-body',
        html: '<p>safe</p><script>private-mail-script</script>',
        attachments: [
          { filename: 'fixture.bin', content: { bytes: new Uint8Array([0, 1, 2, 253, 254, 255]) } },
        ],
      });
    await app.telemetry.flush();
    await app.logger.flush();
    const log = logs.join(''),
      logsPrivate = ![
        'sender@example.test',
        'recipient@example.test',
        'mail-user',
        'mail-pass',
        'private-mail-body',
        'private-mail-script',
      ].some((value) => log.includes(value));
    return {
      transportVerified: health.available,
      accepted: receipt.accepted.length,
      logsPrivate,
      logObserved: logs.some((line) => line.includes('mail.operation.complete')),
    };
  } finally {
    try {
      await app.stop();
    } finally {
      destination.end();
    }
  }
}
/** Run a real isolated SMTP sink and SDK collector; trust its ephemeral CA only in the child. */
export async function runMailExample() {
  const directory = await mkdtemp(join(tmpdir(), 'arkenivajs-mail-example-'));
  await chmod(directory, 0o700);
  const messages: Buffer[] = [],
    envelopes: {
      resourceMetrics?: { scopeMetrics: { metrics: { name: string; unit: string }[] }[] }[];
    }[] = [];
  let smtp: SMTPServer | undefined, key: Buffer | undefined;
  const collector = createServer(async (request, response) => {
    const parts: Buffer[] = [];
    let length = 0;
    for await (const chunk of request) {
      length += chunk.byteLength;
      if (length > 1048576) {
        request.destroy();
        return;
      }
      parts.push(chunk);
    }
    envelopes.push(JSON.parse(Buffer.concat(parts).toString('utf8')));
    response.setHeader('content-type', 'application/json');
    response.end('{}');
  });
  try {
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
    key = await readFile(join(directory, 'server.key'));
    smtp = new SMTPServer({
      key,
      cert: await readFile(join(directory, 'server.pem')),
      logger: false,
      secure: false,
      closeTimeout: 100,
      disableReverseLookup: true,
      onAuth(auth, session, done) {
        if (!session.secure || auth.username !== 'mail-user' || auth.password !== 'mail-pass') {
          done(new Error('The disposable SMTP credentials were rejected'));
          return;
        }
        done(null, { user: 'mail-user' });
      },
      onData(stream, _session, done) {
        const parts: Buffer[] = [];
        let length = 0;
        stream.on('data', (bytes: Buffer) => {
          length += bytes.byteLength;
          if (length > 65536) stream.destroy(new Error('The fixture message exceeded its budget'));
          else parts.push(bytes);
        });
        stream.on('error', () => undefined);
        stream.on('end', () => {
          messages.push(Buffer.concat(parts));
          done(null, 'Fixture accepted');
        });
      },
    });
    smtp.on('error', () => undefined);
    await new Promise<void>((resolve) => smtp!.listen(0, '127.0.0.1', resolve));
    await new Promise<void>((resolve) => collector.listen(0, '127.0.0.1', resolve));
    const smtpAddress = smtp.server.address(),
      metricAddress = collector.address();
    if (
      !smtpAddress ||
      typeof smtpAddress !== 'object' ||
      !metricAddress ||
      typeof metricAddress !== 'object'
    )
      throw new Error('The disposable endpoints did not bind');
    const result = await execute(
      process.execPath,
      [
        fileURLToPath(import.meta.url),
        '--client',
        String(smtpAddress.port),
        String(metricAddress.port),
      ],
      {
        timeout: 10000,
        env: {
          LANG: 'C.UTF-8',
          TZ: 'UTC',
          ARKENIVA_MAIL_DISPOSABLE: '1',
          NODE_EXTRA_CA_CERTS: join(directory, 'server.pem'),
          ...(process.env.NODE_V8_COVERAGE
            ? { NODE_V8_COVERAGE: process.env.NODE_V8_COVERAGE }
            : {}),
        },
      },
    );
    if (result.stderr || messages.length !== 1)
      throw new Error('The disposable SMTP fixture did not complete exactly one submission');
    const receipt = JSON.parse(result.stdout) as Awaited<ReturnType<typeof client>>,
      parsed = await simpleParser(messages[0]!),
      metrics = envelopes
        .flatMap((envelope) => envelope.resourceMetrics ?? [])
        .flatMap((resource) => resource.scopeMetrics.flatMap((scope) => scope.metrics)),
      wire = JSON.stringify(envelopes);
    return Object.freeze({
      ...receipt,
      messages: messages.length,
      attachmentVerified:
        parsed.attachments[0]?.content.equals(Buffer.from([0, 1, 2, 253, 254, 255])) === true,
      htmlSanitized: typeof parsed.html === 'string' && !parsed.html.includes('<script'),
      metricsObserved:
        metrics.some((metric) => metric.name === 'mail.duration.ms' && metric.unit === 'ms') &&
        metrics.some((metric) => metric.name === 'mail.attachment.bytes' && metric.unit === 'By'),
      metricsPrivate: ![
        'sender@example.test',
        'recipient@example.test',
        'mail-pass',
        'private-mail-body',
      ].some((value) => wire.includes(value)),
    });
  } finally {
    try {
      if (smtp) await new Promise<void>((resolve) => smtp!.close(resolve));
    } finally {
      collector.closeAllConnections();
      if (collector.listening)
        await new Promise<void>((resolve) => collector.close(() => resolve()));
      key?.fill(0);
      await rm(directory, { recursive: true, force: true });
    }
  }
}
if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  if (process.argv[2] === '--client')
    console.log(JSON.stringify(await client(Number(process.argv[3]), Number(process.argv[4]))));
  else console.log(JSON.stringify(await runMailExample()));
}
