<!--
SPDX-License-Identifier: AGPL-3.0-or-later
Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>
-->

# Transactional SMTP mail

Register `mailPlugin(settings)`, start the application and resolve `MAIL_CAPABILITY`
as `MailService`. `send` returns immutable SMTP recipient outcomes; acceptance does
not confirm delivery. `verifyTransport` performs an actual TLS/authentication probe;
an unavailable transport reports `available: false`. `close` is idempotent and owned
by application shutdown. Importing the module opens no connections and loads no secrets.

Configure 1–16 distinct named SMTP profiles with fixed host/port, `requireTls: true`,
1–64 allowed sender addresses and a positive attachment cap up to 32 MiB. Credentials
use paired `usernameRef`/`passwordRef` and an application-injected `SecretProvider`.
Without either reference, an explicitly configured TLS relay may be unauthenticated.
Provider values require owned UTF-8 bytes, a nonempty version and a valid future
expiry when present. Failure, absence or expiry never falls back to cached credentials
or anonymous submission. Credentials are consulted on every operation, even when
a pool is warm. Changed values or versions retire that lane before authenticating anew.
Provider byte arrays are copied; only the private copies are cleared after decoding.
Native SMTP authentication necessarily retains strings in the active pool's memory.
No credentials, derived values or references are persisted or logged.

Select a named profile with `MailOperationOptions.transport` on `send` or
`verifyTransport`. Existing `OperationOptions` remain assignable. A single configured
profile permits omission; several profiles require the explicit name. A missing or
unknown selection fails before provider/network activity. Request data cannot set
SMTP hosts, TLS overrides, native options or connection URLs.

Nodemailer 10.2.1 owns SMTP, TLS negotiation, MIME, header encoding and pooling.
Port 465 uses implicit TLS; other ports require STARTTLS. Certificate/hostname checks
remain enabled with TLS 1.2 minimum. Trusted private roots use Node's startup trust
configuration, never a request-controlled bypass. A finite set of 1–8 pool lanes
admits one operation each with one reusable native connection. There is no application
admission queue; the native lane has at most its single admitted message queued.
Idle pools expire; closing/replacement sockets settle before another is opened.
One operation's abort destroys only its lane, including its actual connected socket.

The native pool has `maxRequeues: 0`. A timeout/lost acknowledgement after submission
has `details.outcome: 'unknown'`; it is never retried automatically. The caller must
not infer non-delivery from that error. Explicit caller retries can duplicate mail.
Partial and complete recipient rejection return `partial`/`rejected` receipts with
the actual native recipient lists. Recipient counts are not silently truncated.

Messages require an allowed sender, at least one envelope recipient across To/Cc/Bcc,
and text or HTML. The total recipient cap is 100, attachment cap is 32 entries,
subject cap is 998 UTF-8 bytes, display-name cap is 256 and body parts cap is 1 MiB.
Mailbox syntax uses validator 13.15.35; domains are IDNA-normalized and Unicode
display names remain intact. Header controls, invalid UTF-16, unknown/accessor
properties and unsafe attachment names/types reject before secrets or SMTP.
Attachment content is exactly explicit bytes or an asynchronous byte stream.
File paths, URLs, custom headers and raw MIME are not public inputs. Native file/URL
access is disabled in both MIME construction and transport. Bcc stays in the envelope
and is omitted from MIME headers.

HTML is sanitized with sanitize-html 2.18.1's restrictive tag/attribute defaults and
HTTP/HTTPS/mailto schemes; executable tags, events, arbitrary styles and file URLs
are removed. Named trusted templates use mustache 4.2.0 with escaped scalar bindings
and comments. Raw bindings, loops, lambdas, partial loaders and delimiter changes are
unsupported and fail at startup. Native tokens are bounded to 1024 per template,
64 templates, 64 KiB each and 1 MiB total. Models are snapshotted as bounded JSON
data (depth 16, 4096 nodes, 256 KiB strings/keys) without invoking getters or inherited
methods. Referenced values must be scalars; unknown values render empty. Rendered
size is checked before native concatenation; sanitization follows rendering.

Required policy bounds are positive safe-integer concurrency and `timeoutMs`
(maximum 120000). Optional input/output defaults are 10/16 MiB, each capped at
64 MiB. Input counts message metadata and total raw attachment bytes; output bounds
the native MIME payload, before SMTP framing/TLS, rather than claiming wire-byte
accounting. Attachment source read-ahead is bounded; all consumed bytes count across
attachments. Per-call deadlines can only tighten deployment policy. Arbitrary abort
reasons never cross the safe error boundary. Expired work cannot acknowledge success.
Native/provider/source tasks are observed from birth and retain physical admission
until settled. An uncooperative application source/provider cannot be preempted by
JavaScript; shutdown remains bounded by the core's shared positive deadline.

Errors are `EK_MAIL_CONFIG`, `EK_MAIL_SEND`, `EK_MAIL_REJECTED` and common
`EK_ABORTED`, `EK_TIMEOUT`, `EK_RESOURCE_CLOSED`. Native causes and server replies
remain private. Optional existing logger/telemetry plugins export duration, consumed
attachment bytes, actual accepted/rejected counts and a closed error-class catalog.
Instruments are `mail.duration.ms`, `mail.attachment.bytes`,
`mail.accepted.recipients`, `mail.rejected.recipients`; fixed labels are
`mail.operation`, `mail.outcome`, `mail.error`. No recipient, subject, body, server,
credential, message ID or template/model value is logged or used as a metric label.
Observer failure cannot alter a receipt, reread an attachment or retry SMTP.

The [runnable example](../../examples/mail/README.md) uses a real disposable SMTP
server, ephemeral test CA, native MIME parser and actual Pino/OTel owners. It installs
no system service or trust anchor. Functional, concurrency, TLS, privacy and packed
artifact checks are separate from performance and remote architecture release gates.
