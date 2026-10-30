// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { grpcPlugin, GRPC_CAPABILITY } from '@arkenivajs/grpc';
import { mtlsPlugin } from '@arkenivajs/security-mtls';
import { runPureWorker } from './pure-worker.mjs';
import { nativeGrpc, grpcSettings, grpcMtlsSettings, verifyGrpc } from './grpc-workload.mjs';

runPureWorker({
  name: 'grpc',
  native: nativeGrpc,
  framework: (fixture) => ({
    plugins: [mtlsPlugin(grpcMtlsSettings(fixture))],
    plugin: grpcPlugin(grpcSettings(fixture)),
    key: GRPC_CAPABILITY,
  }),
  verify: verifyGrpc,
  close: (service) => service?.close(),
});
