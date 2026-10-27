// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { newProject, addModule, MODULES } from '../../dist/index.js';
import type { ProjectOptions, ProjectChange } from '../../dist/index.js';

const options: ProjectOptions = { cwd: '/owned', frameworkVersion: '1.0.0', timeoutMs: 1000 };
const project: Promise<ProjectChange> = newProject('service', options);
const dependency: Promise<ProjectChange> = addModule('dns', options);
// @ts-expect-error The file list cannot be mutated through its public contract.
MODULES.push('unavailable');
// @ts-expect-error Configuration uses the common numeric millisecond timeout.
const invalid: ProjectOptions = { timeoutMs: 'forever' };
// @ts-expect-error Directory selection is a string, not an arbitrary file handle.
newProject('service', { cwd: 1 });
void [project, dependency, invalid];
