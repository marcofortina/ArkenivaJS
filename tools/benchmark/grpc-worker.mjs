// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { grpcPlugin, GRPC_CAPABILITY } from '@arkenivajs/grpc';
import { mtlsPlugin } from '@arkenivajs/security-mtls';
import { resolve } from 'node:path';
import { pathToFileURL } from 'node:url';
import { runPureWorker } from './pure-worker.mjs';
import {
  nativeGrpc,
  grpcSettings,
  grpcMtlsSettings,
  verifyGrpc,
  grpcWorkload,
  grpcObservations,
} from './grpc-workload.mjs';

export const grpcAdapter = {
  name: 'grpc',
  asynchronous: true,
  iterations: 100,
  warmupIterations: 20,
  retainRawSamples: true,
  native: nativeGrpc,
  framework: (fixture) => ({
    plugins: [mtlsPlugin(grpcMtlsSettings(fixture))],
    plugin: grpcPlugin(grpcSettings(fixture)),
    key: GRPC_CAPABILITY,
  }),
  verify: verifyGrpc,
  workload: grpcWorkload,
  complete: grpcObservations,
  close: (service) => service?.close(),
};

if (process.argv[1] && import.meta.url === pathToFileURL(resolve(process.argv[1])).href)
  runPureWorker(grpcAdapter);
