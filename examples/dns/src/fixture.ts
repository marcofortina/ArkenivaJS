// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { createSocket } from 'node:dgram';
import * as packet from 'dns-packet';
import type { Answer, Question } from 'dns-packet';

/** Disposable loopback authority; the existing codec owns DNS wire encoding/decoding. */
export async function startDnsFixture(address = '192.0.2.11') {
  const socket = createSocket('udp4'),
    timers = new Set<NodeJS.Timeout>();
  let closed = false,
    requests = 0;
  function answers(question: Question): Answer[] {
    const common = { name: question.name, ttl: 30, class: 'IN' as const };
    switch (question.type) {
      case 'A':
        return [{ ...common, type: 'A', data: address }];
      case 'AAAA':
        return [{ ...common, type: 'AAAA', data: '2001:db8::1' }];
      case 'CNAME':
        return [{ ...common, type: 'CNAME', data: 'target.internal.test' }];
      case 'NS':
        return [{ ...common, type: 'NS', data: 'ns.internal.test' }];
      case 'PTR':
        return [{ ...common, type: 'PTR', data: 'ptr.internal.test' }];
      case 'MX':
        return [
          { ...common, type: 'MX', data: { preference: 10, exchange: 'mail.internal.test' } },
        ];
      case 'SOA':
        return [
          {
            ...common,
            type: 'SOA',
            data: {
              mname: 'ns.internal.test',
              rname: 'hostmaster.internal.test',
              serial: 42,
              refresh: 300,
              retry: 60,
              expire: 3600,
              minimum: 30,
            },
          },
        ];
      case 'SRV':
        return [
          {
            ...common,
            type: 'SRV',
            data: { priority: 10, weight: 5, port: 5432, target: 'db.internal.test' },
          },
        ];
      case 'TXT':
        return [
          { ...common, type: 'TXT', data: [Buffer.from('first'), Buffer.from('second')] },
          { ...common, type: 'TXT', data: [Buffer.from('separate')] },
        ];
      case 'CAA':
        return [
          { ...common, type: 'CAA', data: { flags: 0, tag: 'issue', value: 'ca.internal.test' } },
        ];
      case 'NAPTR':
        return [
          {
            ...common,
            type: 'NAPTR',
            data: {
              order: 10,
              preference: 20,
              flags: 'S',
              services: 'SIP+D2U',
              regexp: '',
              replacement: '_sip._udp.internal.test',
            },
          },
        ];
      default:
        return [];
    }
  }
  socket.on('error', () => undefined);
  socket.on('message', (message, remote) => {
    try {
      const query = packet.decode(message),
        question = query.questions?.[0];
      if (closed || !question) return;
      requests++;
      if (question.name.startsWith('timeout.')) return;
      const missing = question.name.startsWith('missing.'),
        empty = question.name.startsWith('empty.'),
        unavailable = question.name.startsWith('failure.');
      const response = packet.encode({
        type: 'response',
        id: query.id,
        flags:
          packet.AUTHORITATIVE_ANSWER |
          packet.RECURSION_AVAILABLE |
          (missing ? 3 : unavailable ? 2 : 0),
        questions: query.questions ?? [],
        answers: missing || empty || unavailable ? [] : answers(question),
      });
      const send = () => {
        if (!closed) socket.send(response, remote.port, remote.address);
      };
      if (question.name.startsWith('delayed.')) {
        const timer = setTimeout(() => {
          timers.delete(timer);
          send();
        }, 30);
        timers.add(timer);
      } else send();
    } catch {
      /* This disposable fixture ignores malformed packets and never forwards queries. */
    }
  });
  await new Promise<void>((resolve, reject) => {
    socket.once('error', reject);
    socket.bind(0, '127.0.0.1', () => {
      socket.off('error', reject);
      resolve();
    });
  });
  const endpoint = socket.address();
  return Object.freeze({
    server: '127.0.0.1:' + endpoint.port,
    get requests() {
      return requests;
    },
    async close() {
      if (closed) return;
      closed = true;
      for (const timer of timers) clearTimeout(timer);
      timers.clear();
      await new Promise<void>((resolve) => socket.close(() => resolve()));
    },
  });
}
