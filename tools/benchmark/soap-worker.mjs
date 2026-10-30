// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { soapPlugin, SOAP_CAPABILITY } from '@arkenivajs/soap';
import { runPureWorker } from './pure-worker.mjs';
import { nativeSoap, soapSettings, verifySoap } from './soap-workload.mjs';

runPureWorker({
  name: 'soap',
  native: nativeSoap,
  framework: (fixture) => ({ plugin: soapPlugin(soapSettings(fixture)), key: SOAP_CAPABILITY }),
  verify: verifySoap,
  close: (service) => service?.close(),
});
