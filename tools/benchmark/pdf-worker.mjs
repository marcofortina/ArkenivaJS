// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { documentsPdfPlugin, PDF_CAPABILITY } from '@arkenivajs/documents-pdf';
import { runPureWorker } from './pure-worker.mjs';
import { pdfSettings, nativePdf, verifyPdf } from './pdf-workload.mjs';

runPureWorker({
  name: 'pdf',
  asynchronous: true,
  native: nativePdf,
  framework: () => ({ plugin: documentsPdfPlugin(pdfSettings), key: PDF_CAPABILITY }),
  verify: verifyPdf,
  workload() {
    throw new Error('PDF sampling requires complete native child process resource accounting');
  },
});
