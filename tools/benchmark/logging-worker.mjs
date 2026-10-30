// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { runPureWorker } from './pure-worker.mjs';
import { createLoggingAdapter } from './logging-workload.mjs';
runPureWorker(createLoggingAdapter());
