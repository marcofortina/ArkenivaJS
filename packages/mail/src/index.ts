// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { Readable } from 'node:stream';
import { performance } from 'node:perf_hooks';
import MailComposer from 'nodemailer/lib/mail-composer';
import type { SMTPPoolSentMessageInfo } from 'nodemailer';
import { KitError, COMPONENTS } from '@arkenivajs/core';
import { within, SUPPORT_PLUGINS } from '@arkenivajs/core/support';
import type { Plugin, Logger, Telemetry } from '@arkenivajs/core';
import type { ComposablePlugin, SupportPluginFactory } from '@arkenivajs/core/support';
import type {
  MailMessage,
  MailOperationOptions,
  MailPluginSettings,
  MailService,
  MailReceipt,
} from './contracts.js';
import { capture, operation, failure, array, address, text } from './settings.js';
import { message, templates } from './messages.js';
import {
  lanes,
  Job,
  pool,
  credentials,
  attachment,
  retire,
  safeFailure,
  classify,
} from './runtime.js';
export type * from './contracts.js';

interface Observers {
  readonly logger: Logger | undefined;
  readonly telemetry: Telemetry | undefined;
}
const OBSERVERS = Symbol('mail.observers');
const observers: SupportPluginFactory = (options) => {
  const logger = options.plugins?.find((entry) => entry.capabilities.has('logger')),
    telemetry = options.plugins?.find((entry) => entry.capabilities.has('telemetry'));
  return {
    id: 'mail-observers',
    version: '0.1.0',
    capabilities: new Set(),
    dependencies: [
      ...new Set([logger?.id, telemetry?.id].filter((id): id is string => id !== undefined)),
    ],
    init(context) {
      context.provide<Observers>(OBSERVERS, {
        logger: logger ? context.require(COMPONENTS.logger) : undefined,
        telemetry: telemetry ? context.require(COMPONENTS.telemetry) : undefined,
      });
    },
    close() {},
  };
};

/** Explicit application-owned mail capability; importing the module opens no SMTP connection. */
export const MAIL_CAPABILITY: unique symbol = Symbol('arkenivajs.mail');
/** Register finite isolated pool lanes, mandatory TLS and explicitly referenced credentials. */
export function mailPlugin(settings: MailPluginSettings): Plugin {
  let captured: ReturnType<typeof capture>, render: ReturnType<typeof templates>;
  try {
    captured = capture(settings);
    render = templates(captured);
  } catch {
    throw failure('EK_MAIL_CONFIG');
  }
  const instances = new WeakMap<object, MailService>();
  const plugin: ComposablePlugin = {
    id: 'mail',
    version: '0.1.0',
    capabilities: new Set(['mail']),
    dependencies: ['mail-observers'],
    [SUPPORT_PLUGINS]: [observers],
    init(context) {
      const available = lanes(captured.maxConcurrent);
      const observer = context.require<Observers>(OBSERVERS),
        safe = (action: () => unknown) => {
          try {
            void Promise.resolve(action()).catch(() => undefined);
          } catch {
            /* Observers cannot repeat a submission or source read. */
          }
        },
        observe = (job: Job, operation: 'send' | 'verify', started: number) => {
          const attributes = {
              'mail.operation': operation,
              'mail.outcome': job.error ? 'error' : job.outcome,
              'mail.error': job.errorClass,
            },
            duration = Math.max(0, performance.now() - started);
          if (observer.telemetry) {
            safe(() =>
              observer.telemetry!.recordHistogram('mail.duration.ms', duration, attributes),
            );
            safe(() =>
              observer.telemetry!.addCounter(
                'mail.attachment.bytes',
                job.attachmentBytes,
                attributes,
              ),
            );
            safe(() =>
              observer.telemetry!.addCounter('mail.accepted.recipients', job.accepted, attributes),
            );
            safe(() =>
              observer.telemetry!.addCounter('mail.rejected.recipients', job.rejected, attributes),
            );
          }
          if (observer.logger)
            safe(() =>
              observer.logger!.debug('mail.operation.complete', {
                ...attributes,
                durationMs: duration,
                attachmentBytes: job.attachmentBytes,
                acceptedCount: job.accepted,
                rejectedCount: job.rejected,
              }),
            );
        };
      let closed = false,
        closing: Promise<void> | undefined;
      const invoke = async <T>(
        policy: ReturnType<typeof operation>,
        work: (job: Job) => Promise<T>,
        kind: 'send' | 'verify',
      ): Promise<T> => {
        if (closed) throw failure('EK_RESOURCE_CLOSED');
        if (policy.signal?.aborted) throw failure('EK_ABORTED');
        const lane = available.find((entry) => entry.current === undefined);
        if (!lane) throw failure('EK_MAIL_SEND');
        const job = new Job(policy, lane);
        const started = performance.now();
        lane.current = job;
        const task = Promise.resolve()
          .then(() => {
            job.check();
            return work(job);
          })
          .then((value) => {
            job.check();
            return value;
          })
          .catch((cause) => {
            const error = safeFailure(cause, job);
            job.cancel(error.code as Parameters<Job['cancel']>[0]);
            throw error;
          });
        // Physical ownership is independent of a public waiter that may already have expired.
        const physical = task
          .then(
            () => undefined,
            () => undefined,
          )
          .then(() => job.finish());
        void physical.catch(() => undefined);
        lane.task = physical;
        try {
          const result = await within(() => task, {
            signal: job.controller.signal,
            timeoutMs: policy.timeoutMs,
          });
          await within(() => physical, {
            signal: job.controller.signal,
            timeoutMs: Math.max(1, Math.ceil(job.deadline - performance.now())),
          });
          job.check();
          lane.current = undefined;
          lane.task = undefined;
          observe(job, kind, started);
          return result;
        } catch (cause) {
          if (cause instanceof KitError && cause.code === 'EK_TIMEOUT') job.cancel('EK_TIMEOUT');
          const error = safeFailure(cause, job);
          job.cancel(error.code as Parameters<Job['cancel']>[0]);
          const drained = physical
            .then(() => job.finish())
            .finally(() => {
              if (lane.current === job) {
                lane.current = undefined;
                lane.task = undefined;
              }
            });
          void drained.catch(() => undefined);
          lane.task = drained;
          observe(job, kind, started);
          throw error;
        }
      };
      const options = (input: MailOperationOptions | undefined) => {
        if (closed) throw failure('EK_RESOURCE_CLOSED');
        try {
          return operation(input, captured);
        } catch {
          throw failure('EK_MAIL_CONFIG');
        }
      };
      const service: MailService = Object.freeze({
        async send(input: MailMessage, inputOptions?: MailOperationOptions): Promise<MailReceipt> {
          const policy = options(inputOptions),
            prepared = message(input, policy.profile, captured, render),
            expected = new Set(
              [...prepared.to, ...prepared.cc, ...prepared.bcc].map((entry) => entry.address),
            );
          return invoke(
            policy,
            async (job) => {
              const auth = await credentials(captured, job),
                transport = await pool(job.lane, policy.profile, auth, job);
              job.check();
              job.inputBytes = prepared.metadataBytes;
              const composed = new MailComposer({
                  // The native composer normalizes its own mailbox objects in place.
                  from: { ...prepared.from },
                  to: prepared.to.map((entry) => ({ ...entry })),
                  cc: prepared.cc.map((entry) => ({ ...entry })),
                  bcc: prepared.bcc.map((entry) => ({ ...entry })),
                  subject: prepared.subject,
                  text: prepared.text,
                  html: prepared.html,
                  attachments: prepared.attachments.map((entry) => ({
                    filename: entry.filename,
                    contentType: entry.contentType,
                    content: attachment(entry.source, job, captured),
                  })),
                  disableFileAccess: true,
                  disableUrlAccess: true,
                  attachDataUrls: false,
                }).compile(),
                source = composed.createReadStream();
              source.on('error', () => {
                if (!job.finishing) job.cancel('EK_MAIL_SEND');
              });
              job.own(source);
              const raw = Readable.from(
                (async function* () {
                  for await (const chunk of source) {
                    job.check();
                    const bytes = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk);
                    job.outputBytes += bytes.byteLength;
                    if (job.outputBytes > captured.maxOutputBytes) {
                      job.cancel('EK_MAIL_SEND');
                      throw failure('EK_MAIL_SEND', true);
                    }
                    yield bytes;
                  }
                })(),
                { objectMode: false, highWaterMark: 16384 },
              );
              raw.on('error', () => {
                if (!job.finishing) job.cancel('EK_MAIL_SEND');
              });
              job.own(raw);
              job.check();
              job.sendStarted = true;
              let info: SMTPPoolSentMessageInfo;
              try {
                info = await job.wait(
                  transport.sendMail({
                    raw,
                    envelope: composed.getEnvelope(),
                    messageId: composed.messageId(),
                    disableFileAccess: true,
                    disableUrlAccess: true,
                  }),
                );
              } catch (cause) {
                classify(cause, job);
                const nativeCode =
                    cause && typeof cause === 'object'
                      ? Object.getOwnPropertyDescriptor(cause, 'code')?.value
                      : undefined,
                  rejected =
                    cause && typeof cause === 'object'
                      ? Object.getOwnPropertyDescriptor(cause, 'rejected')?.value
                      : undefined;
                if (!job.error && nativeCode === 'EENVELOPE' && Array.isArray(rejected)) {
                  const addresses = array(rejected, 100).map(address);
                  if (
                    addresses.length &&
                    new Set(addresses).size === expected.size &&
                    addresses.every((value) => expected.has(value))
                  ) {
                    job.outcome = 'rejected';
                    job.rejected = addresses.length;
                    return Object.freeze({
                      accepted: Object.freeze([]),
                      rejected: Object.freeze(addresses),
                      outcome: 'rejected',
                      sentAt: new Date().toISOString(),
                    });
                  }
                }
                throw cause;
              }
              const accepted = array(info.accepted, 100).map(address),
                rejected = array(info.rejected, 100).map(address),
                actual = new Set([...accepted, ...rejected]);
              if (
                actual.size !== expected.size ||
                [...actual].some((value) => !expected.has(value)) ||
                accepted.length + rejected.length !== actual.size
              )
                throw failure('EK_MAIL_SEND', true);
              job.check();
              job.accepted = accepted.length;
              job.rejected = rejected.length;
              job.outcome = accepted.length ? (rejected.length ? 'partial' : 'ok') : 'rejected';
              return Object.freeze({
                transportId: text(info.messageId, 1024, true),
                accepted: Object.freeze(accepted),
                rejected: Object.freeze(rejected),
                outcome: accepted.length ? (rejected.length ? 'partial' : 'accepted') : 'rejected',
                sentAt: new Date().toISOString(),
              });
            },
            'send',
          );
        },
        async verifyTransport(inputOptions?: MailOperationOptions) {
          const policy = options(inputOptions);
          return invoke(
            policy,
            async (job) => {
              const auth = await credentials(captured, job);
              // Verification uses its own native connection; retire an idle lane before opening it.
              await job.wait(retire(job.lane));
              const transport = await pool(job.lane, policy.profile, auth, job);
              let verified = false;
              try {
                verified = await job.wait(transport.verify());
              } catch (cause) {
                job.check();
                classify(cause, job);
              } finally {
                await job.wait(retire(job.lane));
              }
              job.check();
              job.outcome = verified === true ? 'ok' : 'error';
              return Object.freeze({
                available: verified === true,
                checkedAt: new Date().toISOString(),
              });
            },
            'verify',
          );
        },
        async close() {
          if (!closing) {
            closed = true;
            for (const lane of available) lane.current?.cancel('EK_RESOURCE_CLOSED');
            const cleanup = Promise.all([
              ...available.map((lane) => retire(lane)),
              ...available.flatMap((lane) => (lane.task ? [lane.task] : [])),
            ]).then(() => undefined);
            void cleanup.catch(() => undefined);
            closing = within(() => cleanup, { timeoutMs: captured.timeoutMs });
            void closing.catch(() => undefined);
          }
          await closing;
        },
      });
      instances.set(context, service);
      context.provide(MAIL_CAPABILITY, service);
    },
    async close(context) {
      await instances.get(context)?.close();
      instances.delete(context);
    },
  };
  return plugin;
}
