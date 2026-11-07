// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import assert from 'node:assert/strict';
import { writeFile } from 'node:fs/promises';
import { resolve } from 'node:path';
import { countSensitiveValues, fingerprint } from './mfa-privacy.mjs';

/** Retain one raw credential profile without treating it as accepted measurement evidence. */
export async function writeApiKeyObservation(directory, observation, privateFingerprints) {
  const { mode, sourceCommit, workingTreeDirty, sourceFilesSha256, report, providerCalls } =
    observation;
  assert.ok(['BASELINE', 'FRAMEWORK', 'STANDARD', 'DETAILED'].includes(mode));
  const raw = {
    validation: 'UNVERIFIED',
    releaseGate: false,
    mode,
    sourceCommit,
    workingTreeDirty,
    sourceFilesSha256,
    report,
    providerCalls,
  };
  const corpus = new Set(privateFingerprints),
    comparisons = new Set([...corpus].map(fingerprint));
  const assertPrivate = (value) => {
    assert.equal(
      countSensitiveValues(value, corpus),
      0,
      'Credential observations contain private material',
    );
    assert.equal(
      countSensitiveValues(value, comparisons),
      0,
      'Credential observations contain private comparison fingerprints',
    );
  };
  assertPrivate(raw);
  const serialized =
    JSON.stringify(
      raw,
      (key, value) => {
        assertPrivate(key);
        if (typeof value === 'string') assertPrivate(value);
        return value;
      },
      2,
    ) + '\n';
  await writeFile(resolve(directory, mode.toLowerCase() + '-observations.json'), serialized, {
    mode: 0o600,
    flag: 'wx',
  });
}
