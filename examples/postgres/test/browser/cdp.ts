// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

/** Bounded CDP transport for an explicitly configured disposable loopback browser only. */
export async function connectBrowser(address: string) {
  const endpoint = new URL(address);
  if (
    endpoint.protocol !== 'http:' ||
    endpoint.hostname !== '127.0.0.1' ||
    endpoint.username ||
    endpoint.password ||
    endpoint.pathname !== '/' ||
    endpoint.search ||
    endpoint.hash
  )
    throw new Error('An explicit disposable loopback browser endpoint is required');
  const response = await fetch(new URL('/json/version', endpoint), {
    signal: AbortSignal.timeout(5000),
    redirect: 'error',
  });
  const text = await response.text();
  if (!response.ok || text.length > 16384) throw new Error('Browser metadata is unavailable');
  const version = JSON.parse(text) as { webSocketDebuggerUrl?: string; Browser?: string };
  if (typeof version.webSocketDebuggerUrl !== 'string')
    throw new Error('Browser endpoint is unavailable');
  const socketUrl = new URL(version.webSocketDebuggerUrl);
  if (
    socketUrl.protocol !== 'ws:' ||
    !['127.0.0.1', 'localhost'].includes(socketUrl.hostname) ||
    socketUrl.username ||
    socketUrl.password
  )
    throw new Error('Browser WebSocket is not loopback');
  socketUrl.host = endpoint.host;
  const socket = new WebSocket(socketUrl);
  const pending = new Map<
    number,
    {
      resolve(value: Record<string, unknown>): void;
      reject(error: Error): void;
      timer: ReturnType<typeof setTimeout>;
    }
  >();
  const failure = () => new Error('Disposable browser command failed');
  let serial = 0;
  const fail = () => {
    for (const entry of pending.values()) {
      clearTimeout(entry.timer);
      entry.reject(failure());
    }
    pending.clear();
  };
  socket.addEventListener('close', fail);
  socket.addEventListener('error', fail);
  socket.addEventListener('message', (event) => {
    try {
      if (typeof event.data !== 'string' || Buffer.byteLength(event.data) > 2 * 1024 * 1024)
        throw failure();
      const message = JSON.parse(event.data) as {
        id?: number;
        error?: unknown;
        result?: Record<string, unknown>;
      };
      if (message.id === undefined) return;
      const entry = pending.get(message.id);
      if (!entry) return;
      pending.delete(message.id);
      clearTimeout(entry.timer);
      if (message.error || !message.result) entry.reject(failure());
      else entry.resolve(message.result);
    } catch {
      fail();
      socket.close();
    }
  });
  await new Promise<void>((resolve, reject) => {
    const timer = setTimeout(() => {
      socket.close();
      reject(failure());
    }, 5000);
    socket.addEventListener(
      'open',
      () => {
        clearTimeout(timer);
        resolve();
      },
      { once: true },
    );
    socket.addEventListener(
      'error',
      () => {
        clearTimeout(timer);
        reject(failure());
      },
      { once: true },
    );
  });
  const call = (
    method: string,
    params: Record<string, unknown> = {},
    sessionId?: string,
  ): Promise<Record<string, unknown>> => {
    if (pending.size >= 8 || socket.readyState !== WebSocket.OPEN) return Promise.reject(failure());
    const id = ++serial,
      serialized = JSON.stringify({
        id,
        method,
        params,
        ...(sessionId === undefined ? {} : { sessionId }),
      });
    if (Buffer.byteLength(serialized) > 2 * 1024 * 1024) return Promise.reject(failure());
    return new Promise((resolve, reject) => {
      const timer = setTimeout(() => {
        pending.delete(id);
        reject(failure());
      }, 10000);
      pending.set(id, { resolve, reject, timer });
      socket.send(serialized);
    });
  };
  let targetId: string | undefined;
  try {
    const target = await call('Target.createTarget', { url: 'about:blank' });
    if (typeof target.targetId !== 'string') throw failure();
    targetId = target.targetId;
    const attached = await call('Target.attachToTarget', { targetId, flatten: true });
    if (typeof attached.sessionId !== 'string') throw failure();
    const sessionId = attached.sessionId;
    const command = (method: string, params?: Record<string, unknown>) =>
      call(method, params, sessionId);
    return {
      version: version.Browser,
      command,
      async evaluate(expression: string) {
        const response = await command('Runtime.evaluate', {
          expression,
          awaitPromise: true,
          returnByValue: true,
          userGesture: true,
        });
        if (response.exceptionDetails) throw failure();
        const result = response.result as { value?: unknown } | undefined;
        if (!result) throw failure();
        return result.value;
      },
      async close() {
        try {
          await call('Target.closeTarget', { targetId });
        } finally {
          fail();
          socket.close();
        }
      },
    };
  } catch (error) {
    if (targetId) await call('Target.closeTarget', { targetId }).catch(() => undefined);
    fail();
    socket.close();
    throw error;
  }
}
