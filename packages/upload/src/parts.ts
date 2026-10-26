// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import type { FastifyRequest } from 'fastify';
import type { MultipartFile } from '@fastify/multipart';
import { within } from '@arkenivajs/core/support';
import type { OperationOptions } from '@arkenivajs/core';
import type { MultipartPart, UploadPolicy } from './contracts.js';
import { failure, text } from './policy.js';
import { discardOptions, RequestScope } from './runtime.js';

function metadata(input: string, maximum: number): string {
  try {
    return text(input, maximum).normalize('NFC');
  } catch {
    throw failure('EK_UPLOAD_STREAM');
  }
}
/** The native parser owns syntax, MIME boundaries and backpressure; this adapter owns policy. */
export function parts(
  request: FastifyRequest,
  scope: RequestScope,
  policy: UploadPolicy,
): AsyncIterable<MultipartPart> {
  let used = false;
  return Object.freeze({
    [Symbol.asyncIterator](): AsyncIterator<MultipartPart> {
      if (used) throw scope.fail('EK_UPLOAD_STREAM');
      used = true;
      let previous: { complete: boolean } | undefined,
        finished = false,
        busy = false;
      const source = request.parts({
        preservePath: true,
        highWaterMark: 16384,
        fileHwm: 16384,
        limits: {
          fieldNameSize: 256,
          fieldSize: policy.maxFieldBytes + 1,
          files: policy.maxFiles,
          fields: policy.maxFields,
          parts: policy.maxParts,
          fileSize: policy.maxFileBytes + 1,
          headerPairs: 32,
          headerSize: 8192,
        },
      });
      const convert = (part: MultipartFile): MultipartPart => {
        scope.stream(part.file);
        const fieldName = metadata(part.fieldname, 256),
          filename = metadata(part.filename, 256);
        if (/[/\\:]/.test(filename) || ['.', '..'].includes(filename))
          throw scope.fail('EK_UPLOAD_STREAM');
        const declaredMediaType = metadata(part.mimetype, 127).toLowerCase();
        if (!policy.allowedMediaTypes.includes(declaredMediaType))
          throw scope.fail('EK_UPLOAD_MEDIA_TYPE');
        scope.files++;
        const state = { complete: false },
          file = part.file;
        previous = state;
        let claimed = false,
          bytes = 0;
        const stream: AsyncIterable<Uint8Array> = Object.freeze({
          [Symbol.asyncIterator](): AsyncIterator<Uint8Array> {
            if (claimed) throw scope.fail('EK_UPLOAD_STREAM');
            claimed = true;
            return (async function* () {
              try {
                for await (const chunk of file) {
                  scope.check();
                  if (!(chunk instanceof Uint8Array)) throw scope.fail('EK_UPLOAD_STREAM');
                  bytes += chunk.byteLength;
                  if (bytes > policy.maxFileBytes || file.truncated)
                    throw scope.fail('EK_UPLOAD_LIMIT');
                  yield chunk;
                }
                scope.check();
                if (file.truncated) throw scope.fail('EK_UPLOAD_LIMIT');
                state.complete = true;
              } catch (cause) {
                throw scope.translate(cause);
              } finally {
                if (!state.complete) file.destroy(scope.fail('EK_UPLOAD_TRUNCATED'));
              }
            })();
          },
        });
        return Object.freeze({
          kind: 'file' as const,
          fieldName,
          filename,
          declaredMediaType,
          stream,
          async discard(options?: OperationOptions) {
            const operation = discardOptions(options, scope);
            try {
              const task = scope.watch(
                (async () => {
                  for await (const chunk of stream) void chunk;
                })(),
              );
              await within(() => task, operation);
              scope.check();
            } catch (cause) {
              throw scope.translate(cause);
            }
          },
        });
      };
      return {
        async next() {
          if (busy || finished || (previous && !previous.complete)) {
            if (finished && scope.exhausted) return { done: true, value: undefined };
            throw scope.fail('EK_UPLOAD_STREAM');
          }
          busy = true;
          try {
            scope.check();
            const part = await scope.run(() => source.next());
            if (part.done) {
              finished = true;
              scope.exhausted = true;
              return { done: true, value: undefined };
            }
            if (++scope.parts > policy.maxParts) throw scope.fail('EK_UPLOAD_LIMIT');
            if (part.value.type === 'file') return { done: false, value: convert(part.value) };
            const field = part.value;
            if (
              field.fieldnameTruncated ||
              field.valueTruncated ||
              typeof field.value !== 'string' ||
              Buffer.byteLength(field.value) > policy.maxFieldBytes
            )
              throw scope.fail('EK_UPLOAD_LIMIT');
            return {
              done: false,
              value: Object.freeze({
                kind: 'field' as const,
                fieldName: metadata(field.fieldname, 256),
                value: field.value,
              }),
            };
          } catch (cause) {
            throw scope.translate(cause);
          } finally {
            busy = false;
          }
        },
        async return() {
          if (!scope.exhausted) scope.fail('EK_UPLOAD_TRUNCATED');
          finished = true;
          // Do not wait for an upstream iterator that requires the rejected file to be drained.
          if (source.return) void scope.watch(source.return(undefined)).catch(() => undefined);
          return { done: true, value: undefined };
        },
      };
    },
  });
}
