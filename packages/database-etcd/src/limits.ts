// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

/** Explicit portable limits leave larger native operations under caller ownership. */
export const ETCD_LIMITS = Object.freeze({
  pending: 128,
  keyBytes: 4096,
  valueBytes: 1_048_576,
  watches: 64,
  watchEvents: 256,
  watchBytes: 2_097_152,
  leases: 64,
  timeoutMs: 15_000,
  startupMs: 5000,
  cleanupMs: 5000,
  shutdownMs: 20_000,
});
