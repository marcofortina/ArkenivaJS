// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { createHash } from 'node:crypto';

/** Ephemeral leakage-test comparison only; neither credential storage nor a published secret verifier. */
export const fingerprint = (value) => createHash('sha256').update(value).digest('hex');

/** Inspect bounded JSON data without retaining factor material or invoking object accessors. */
export function countSensitiveValues(value, fingerprints) {
  const hashes = fingerprints instanceof Set ? fingerprints : new Set(fingerprints);
  if (hashes.size > 250000) throw new Error('Privacy fingerprint capacity exceeded');
  const pending = [value],
    seen = new WeakSet();
  let count = 0,
    visited = 0;
  while (pending.length) {
    if (++visited > 1000000) throw new Error('Privacy input capacity exceeded');
    const item = pending.pop();
    if (typeof item === 'string') {
      if (item.length > 2097152) throw new Error('Privacy string capacity exceeded');
      if (hashes.has(fingerprint(item))) count++;
      const matches = item.matchAll(
        /otpauth:\/\/[^\s"'<>]+|(?<![A-Za-z0-9_-])[A-Za-z0-9_-]{32,2048}(?![A-Za-z0-9_-])|\b\d{6}\b/g,
      );
      for (const match of matches) if (hashes.has(fingerprint(match[0]))) count++;
    } else if (item && typeof item === 'object' && !seen.has(item)) {
      seen.add(item);
      for (const field of Object.values(Object.getOwnPropertyDescriptors(item))) {
        if (!('value' in field)) throw new Error('Privacy input must contain only data properties');
        pending.push(field.value);
      }
    }
  }
  return count;
}
