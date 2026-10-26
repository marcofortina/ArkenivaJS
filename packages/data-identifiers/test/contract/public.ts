// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { createIdentifiersService, dataIdentifiersPlugin } from '../../dist/index.js';
import type { IdentifiersService, ParsedUuid } from '../../dist/index.js';

/** Compile public signatures without executing generation or malformed requests. */
export function publicContract(ids: IdentifiersService, parsed: ParsedUuid) {
  createIdentifiersService({ allowVersions: [4, 7] });
  dataIdentifiersPlugin({ allowVersions: [7] });
  // @ts-expect-error Only the prescribed identifier versions are supported.
  dataIdentifiersPlugin({ allowVersions: [1] });
  // @ts-expect-error No caller-provided RNG or clock is exposed.
  createIdentifiersService({ allowVersions: [7], now: 0 });
  // @ts-expect-error Parsed metadata remains immutable.
  parsed.version = 7;
  return [ids.uuidV4(), ids.uuidV7(), ids.parseUuid('invalid'), ids.isUuid('invalid', 4)];
}
