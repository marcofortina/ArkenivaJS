// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

export type * from './contracts.js';
export { graphqlPlugin } from './plugin.js';

/** Identity for the optional GraphQL administrative capability. */
export const GRAPHQL_CAPABILITY: unique symbol = Symbol('arkenivajs.graphql');
