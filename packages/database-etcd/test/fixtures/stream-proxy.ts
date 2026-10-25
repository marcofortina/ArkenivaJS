import { createServer, createConnection } from 'node:net';
import type { Socket } from 'node:net';

/** An ephemeral TCP relay interrupts only this test's real TLS connection to its VM fixture. */
export async function streamProxy(target: number) {
  const sockets = new Set<Socket>();
  let blocked = false;
  const server = createServer((incoming) => {
    if (blocked) {
      incoming.destroy();
      return;
    }
    const outgoing = createConnection({ host: '127.0.0.1', port: target });
    sockets.add(incoming);
    sockets.add(outgoing);
    incoming.on('error', () => outgoing.destroy());
    outgoing.on('error', () => incoming.destroy());
    incoming.on('close', () => {
      sockets.delete(incoming);
      outgoing.destroy();
    });
    outgoing.on('close', () => {
      sockets.delete(outgoing);
      incoming.destroy();
    });
    incoming.pipe(outgoing);
    outgoing.pipe(incoming);
  });
  await new Promise<void>((resolve, reject) => {
    server.once('error', reject);
    server.listen(0, '127.0.0.1', resolve);
  });
  const address = server.address();
  if (!address || typeof address === 'string')
    throw new Error('The stream proxy did not obtain a TCP port');
  return {
    port: address.port,
    cut() {
      blocked = true;
      for (const socket of sockets) socket.destroy();
    },
    restore() {
      blocked = false;
    },
    async close() {
      blocked = true;
      for (const socket of sockets) socket.destroy();
      await new Promise<void>((resolve, reject) =>
        server.close((error) => (error ? reject(error) : resolve())),
      );
    },
  };
}
