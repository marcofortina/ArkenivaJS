// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { soapPlugin, SOAP_CAPABILITY } from '@arkenivajs/soap';
import { resolve } from 'node:path';
import { pathToFileURL } from 'node:url';
import { runPureWorker } from './pure-worker.mjs';
import {
  nativeSoap,
  soapSettings,
  verifySoap,
  soapWorkload,
  soapObservations,
} from './soap-workload.mjs';

export const soapAdapter = {
  name: 'soap',
  asynchronous: true,
  iterations: 100,
  warmupIterations: 20,
  retainRawSamples: true,
  native: nativeSoap,
  framework: (fixture) => ({ plugin: soapPlugin(soapSettings(fixture)), key: SOAP_CAPABILITY }),
  verify: verifySoap,
  workload: soapWorkload,
  complete: soapObservations,
  close: (service) => service?.close(),
};

if (process.argv[1] && import.meta.url === pathToFileURL(resolve(process.argv[1])).href)
  runPureWorker(soapAdapter);
