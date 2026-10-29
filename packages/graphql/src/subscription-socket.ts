// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import websocket from '@fastify/websocket';
import type { FastifyInstance } from 'fastify';
import { failure } from './policy.js';

/** One native upgrade dispatcher belongs to the existing application listener, across route scopes. */
export async function subscriptionSocket(server: FastifyInstance, maximum = 1048576) {
  if (server.server.listening || !Number.isSafeInteger(maximum) || maximum < 1) throw failure();
  if (!server.hasDecorator('websocketServer')) {
    await server.register(websocket, {
      options: { maxPayload: Math.max(1048576, maximum), perMessageDeflate: false },
      errorHandler(_error, socket) {
        socket.terminate();
      },
    });
  }
  const options = server.websocketServer.options;
  if (
    options.perMessageDeflate !== false ||
    !Number.isSafeInteger(options.maxPayload) ||
    options.maxPayload! < 1
  )
    throw failure();
  options.maxPayload = Math.max(options.maxPayload!, maximum);
}
