// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import assert from 'node:assert/strict';
import { writeFile } from 'node:fs/promises';
import { resolve } from 'node:path';
import { runPureComparison } from './pure-comparison.mjs';
import { startMailFixture } from './mail-fixture.mjs';
import { mailPrivateValues } from './mail-workload.mjs';
const args = process.argv.slice(2);
assert.ok(
  args.length === 2 && ['--verify', '--smoke'].includes(args[0]),
  'Use --verify or --smoke with a fresh absolute external report directory; full SMTP campaigns remain separate',
);
const measured = args[0] === '--smoke';
if (measured)
  assert.equal(
    process.env.ARKENIVA_MAIL_BENCHMARK_DISPOSABLE,
    '1',
    'SMTP smoke measurements require an explicitly disposable runner',
  );
const authority = await startMailFixture();
try {
  const report = await runPureComparison({
    scenarioId: 'mail-native-functional-comparison',
    fixture: authority.fixture,
    trustAnchorFile: authority.trustAnchorFile,
    privacyValues: [...mailPrivateValues, authority.fixture.credential, authority.trustAnchorFile],
    privacyField: 'inputOccurrences',
    worker: new URL('./mail-worker.mjs', import.meta.url),
    inputs: {
      operations: ['verifyTransport', 'send'],
      nativeBackend: 'nodemailer10.2.1',
      ownedSmtpServer: true,
      mandatoryStartTls: true,
      streamedAttachmentBytes: 6,
      samplingSupported: true,
      scenarios: ['smtp-accepted-streamed-attachment'],
      measuredSamplesPerScenario: measured ? 100 : null,
      warmupCallbacksPerScenario: measured ? 20 : null,
      traceSamplingRatio: { BASELINE: 0, FRAMEWORK: 0, STANDARD: 1, DETAILED: 1 },
      concurrency: 1,
    },
    observationCoverage:
      'Actual owned SMTP verification, STARTTLS authentication and MIME receipt in four isolated profiles; actual standard/detailed exports checked without addresses, content or credentials. Explicit smoke retains actual Tinybench SMTP acceptance latency samples. Independent bounded MIME capture verifies sender, recipient, content, attachment bytes and aggregate receipt integrity against actual callback counts; physical server sessions/parser tasks retire before success. STANDARD and DETAILED both use diagnostic trace sampling1.',
    limitations:
      'Fixed valid MIME corpus only; bare Nodemailer omits framework policy and secret-provider rotation. SMTP acceptance is not delivery. Timed latency awaits actual SMTP acceptance after independent MIME validation. CPU/RSS covers the complete client worker process, excluding the external SMTP server and MIME parser, certificate setup and server socket resources. STANDARD uses diagnostic sampling1 rather than normal production sampling. No recipient delivery, exactly-once submission, complete client/server pipeline cost, policy-equivalent overhead, calibrated budget, confidence interval, repeated campaign or soak acceptance.',
  });
  await authority.quiescent();
  authority.verifyReceipts(report.records.map((row) => row.completion));
  const expectedAccepted = report.records.reduce(
      (sum, row) => sum + row.completion.totalReceipts,
      0,
    ),
    expectedAttachments = report.records.reduce(
      (sum, row) => sum + row.completion.expectedAttachmentBytes,
      0,
    );
  assert.equal(authority.state.acceptedMessages, expectedAccepted);
  assert.equal(authority.state.attachmentBytes, expectedAttachments);
  assert.equal(authority.state.envelopeRecipients, expectedAccepted);
  assert.equal(authority.state.mimeRecipients, expectedAccepted);
  assert.equal(authority.state.failedMessages, 0);
  assert.equal(authority.state.activeMessages, 0);
  assert.equal(authority.state.activeConnections, 0);
  assert.equal(authority.state.connectionsOpened, authority.state.connectionsClosed);
  assert.ok(authority.state.authentications >= 4);
  assert.equal(authority.state.secureSessions, authority.state.authentications);
  await writeFile(
    resolve(args[1], 'protocol-observation.json'),
    JSON.stringify({ ...authority.state, releaseGate: false }, null, 2) + '\n',
    { mode: 0o600, flag: 'wx' },
  );
} finally {
  await authority.close();
}
