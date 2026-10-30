// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import assert from 'node:assert/strict';
import { writeFile } from 'node:fs/promises';
import { resolve } from 'node:path';
import { runPureComparison } from './pure-comparison.mjs';
import { startMailFixture } from './mail-fixture.mjs';
import { mailPrivateValues } from './mail-workload.mjs';
assert.equal(
  process.argv[2],
  '--verify',
  'Only --verify is supported for the owned SMTP functional workload',
);
const authority = await startMailFixture();
try {
  await runPureComparison({
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
      samplingSupported: false,
      concurrency: 1,
    },
    observationCoverage:
      'Actual owned SMTP verification, STARTTLS authentication and MIME receipt in four isolated profiles; actual standard/detailed exports checked without addresses, content or credentials.',
    limitations:
      'Fixed valid MIME corpus only; bare Nodemailer omits framework policy and secret-provider rotation. SMTP acceptance is not delivery. No protocol throughput, total process/socket resource, provider latency, repeated campaign or soak acceptance.',
  });
  assert.equal(authority.state.acceptedMessages, 8);
  assert.equal(authority.state.attachmentBytes, 48);
  assert.ok(authority.state.authentications >= 4);
  assert.equal(authority.state.secureSessions, authority.state.authentications);
  await writeFile(
    resolve(process.argv[3], 'protocol-observation.json'),
    JSON.stringify({ ...authority.state, releaseGate: false }, null, 2) + '\n',
    { mode: 0o600, flag: 'wx' },
  );
} finally {
  await authority.close();
}
