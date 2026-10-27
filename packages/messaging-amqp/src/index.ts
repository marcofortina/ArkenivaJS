// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

export type * from './contracts.js';
/** Symbol reserved for the explicitly installed optional native AMQP adapter. */
export const AMQP_CAPABILITY: unique symbol = Symbol('arkenivajs.messaging.amqp');
