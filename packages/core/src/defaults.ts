// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

/** Maximum default time for cooperative application shutdown, in milliseconds. */
export const DEFAULT_SHUTDOWN_TIMEOUT_MS = 30_000;
/** Default outbound HTTP deadline, in milliseconds. */
export const DEFAULT_HTTP_TIMEOUT_MS = 10_000;
/** Default SQL execution deadline, in milliseconds, including acquisition. */
export const DEFAULT_SQL_TIMEOUT_MS = 15_000;
/** Default native SQL pool acquisition deadline, in milliseconds. */
export const DEFAULT_POOL_ACQUIRE_TIMEOUT_MS = 5000;
/** Maximum pending technical metering events unless explicitly configured. */
export const DEFAULT_METER_QUEUE_CAPACITY = 10_000;
/** Version of the independent technical metering event envelope. */
export const METER_EVENT_SCHEMA_VERSION = '1.0.0';
