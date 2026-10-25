// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

/** Portable bounds retain larger native workloads under explicit caller ownership. */
export const MONGODB_LIMITS = Object.freeze({
  pending: 128,
  transactions: 8,
  documentBytes: 1_048_576,
  resultBytes: 8_388_608,
  defaultRows: 100,
  maximumRows: 1000,
  pipelineStages: 128,
  depth: 64,
  timeoutMs: 15_000,
  startupMs: 5000,
  cleanupMs: 5000,
  shutdownMs: 20_000,
});
