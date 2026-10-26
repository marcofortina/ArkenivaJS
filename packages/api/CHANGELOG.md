# Changelog

## Unreleased

- Map tenant instance capacity rejection to HTTP 503 with the fixed safe error envelope.

## 0.1.0

- Add Fastify routes, strict request/response schemas, OpenAPI 3.1, safe middleware stages and graceful listener lifecycle.
- Use optional declared dependency health for bounded, shared HTTP readiness while preserving local liveness and safe status-only responses.

- Add private bounded TLS-file validation and native key/certificate checks with
  temporary-buffer cleanup and real HTTPS/client-certificate tests.

- Connect explicit HTTP/HTTPS application configuration to startup-only TLS file
  loading, enforce client-certificate/minimum-version policy and preserve routing.
- Keep applications without HTTP configuration free of implicit listeners and
  report bind failures as `EK_HTTP_LISTEN`.

- Enable typed native HTTP/2 with mandatory HTTP/1.1 fallback, bounded session
  policy and graceful/forced cleanup of owned sessions and sockets.
- Verify WSS upgrades using the official Fastify plugin as a development-only
  dependency, with trusted and untrusted TLS client cases.
