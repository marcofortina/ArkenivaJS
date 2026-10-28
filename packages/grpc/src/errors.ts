// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { KitError } from '@arkenivajs/core';
import type { ErrorCode } from '@arkenivajs/core';
export function failure(code: ErrorCode = 'EK_GRPC_AUTH'): KitError {
  const messages: Partial<Record<ErrorCode, string>> = {
    EK_GRPC_AUTH: 'The gRPC peer or request could not be authenticated',
    EK_GRPC_STATUS: 'The gRPC operation failed',
    EK_GRPC_DEADLINE: 'The gRPC operation exceeded its deadline',
    EK_CONFIG_INVALID: 'The gRPC configuration is invalid',
    EK_RESOURCE_CLOSED: 'The gRPC resource is closed',
    EK_BACKEND_UNAVAILABLE: 'The native gRPC backend is unavailable',
  };
  return new KitError({ code, message: messages[code] ?? 'The gRPC operation failed' });
}
