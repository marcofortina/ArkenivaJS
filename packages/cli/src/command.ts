// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { parseArgs } from 'node:util';
import { KitError } from '@arkenivajs/core';
import type { OperationOptions } from '@arkenivajs/core';
import { newProject, addModule, FRAMEWORK_VERSION } from './index.js';

const help =
  'Usage: arkenivajs new <name> | arkenivajs add <module> [--framework-version <exact-version>]\nUse an existing trusted working directory. Commands edit files only; run your package manager explicitly after approved packages are available.\n';
export interface CommandOutput {
  readonly stdout: (text: string) => void;
  readonly stderr: (text: string) => void;
}
/** Node owns argument parsing; errors never echo source file contents or arbitrary command arguments. */
export async function runCli(
  args: readonly string[],
  output: CommandOutput,
  options: OperationOptions & { readonly cwd?: string } = {},
): Promise<number> {
  try {
    if (args.length > 16 || args.some((arg) => typeof arg !== 'string' || arg.length > 4096))
      throw new Error();
    const { values, positionals } = parseArgs({
      args: [...args],
      allowPositionals: true,
      strict: true,
      options: {
        help: { type: 'boolean', short: 'h' },
        version: { type: 'boolean', short: 'v' },
        'framework-version': { type: 'string' },
      },
    });
    if (values.help && positionals.length === 0 && Object.keys(values).length === 1) {
      output.stdout(help);
      return 0;
    }
    if (values.version && positionals.length === 0 && Object.keys(values).length === 1) {
      output.stdout(FRAMEWORK_VERSION + '\n');
      return 0;
    }
    if (
      values.help ||
      values.version ||
      positionals.length !== 2 ||
      !['new', 'add'].includes(positionals[0]!)
    )
      throw new Error();
    const input = {
      ...options,
      ...(values['framework-version'] === undefined
        ? {}
        : { frameworkVersion: values['framework-version'] }),
    };
    const result = await (positionals[0] === 'new'
      ? newProject(positionals[1]!, input)
      : addModule(positionals[1]!, input));
    output.stdout(
      result.changed
        ? 'Project files updated. Install dependencies and configure selected plugins explicitly.\n'
        : 'The selected dependency is already present; no files changed.\n',
    );
    return 0;
  } catch (error) {
    output.stderr(
      JSON.stringify(
        error instanceof KitError
          ? error.toSafeJSON()
          : {
              code: 'EK_CONFIG_INVALID',
              message: 'Invalid command or unavailable project operation',
            },
      ) + '\n',
    );
    return 1;
  }
}
