// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { documentsPdfPlugin, PDF_CAPABILITY } from '@arkenivajs/documents-pdf';
import { runPureWorker } from './pure-worker.mjs';
import { pdfSettings, nativePdf, verifyPdf, pdfInspectWorkload } from './pdf-workload.mjs';

let active;

runPureWorker({
  name: 'pdf',
  asynchronous: true,
  iterations: 100,
  warmupIterations: 20,
  retainRawSamples: true,
  native: nativePdf,
  framework: () => ({ plugin: documentsPdfPlugin(pdfSettings), key: PDF_CAPABILITY }),
  verify: verifyPdf,
  workload(service) {
    active = pdfInspectWorkload(service);
    return active.workload;
  },
  complete(_service, { measure, records }) {
    return measure ? active.complete(records) : undefined;
  },
});
