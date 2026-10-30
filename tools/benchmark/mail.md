# Native SMTP functional comparison

Build the workspace and choose a fresh absolute directory outside Git:

```sh
pnpm --filter @arkenivajs/benchmark-foundation mail --verify /private/mail-verification
```

Four isolated profiles perform actual transport verification and two messages
each through Nodemailer 10.2.1 and the public mail plugin. An ephemeral loopback
SMTP server requires STARTTLS and random disposable credentials. It independently
parses every received MIME message and verifies its text, filename and exact
streamed binary attachment. The protocol report requires eight accepted messages,
48 attachment bytes and authenticated TLS sessions. Acceptance is not delivery.

OpenSSL creates an ephemeral private certificate outside Git. Only the four
worker processes receive its path through Node startup trust configuration.
No system trust or parent environment changes occur. The server, private key,
certificate and directory are removed on success or failure. No mail is forwarded.
The fixture and native baseline use the already pinned smtp-server 3.21.1 and
mailparser 3.12.4. OpenSSL must be available for this local verification.

Only `--verify` is accepted; `--smoke` fails before fixture creation. Reports use
`measured: false`, null resources, no timing samples and `releaseGate: false`.
The baseline shares valid MIME inputs and one pooled connection but omits the
framework's sender, byte, attachment, template and secret-rotation policies.
It cannot prove equivalent security policy or production SMTP throughput.
Actual standard/detailed exports must contain no credentials, recipient addresses,
message text or attachment filename. No performance budget, repeated campaign,
provider latency, durable recipient delivery or one-hour soak is claimed.
