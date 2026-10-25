# Changelog

## 0.1.0

- Add Fastify routes, strict request/response schemas, OpenAPI 3.1, safe middleware stages and graceful listener lifecycle.
- Use optional declared dependency health for bounded, shared HTTP readiness while preserving local liveness and safe status-only responses.

- Add private bounded TLS-file validation and native key/certificate checks with
  temporary-buffer cleanup and real HTTPS/client-certificate tests.

- Connect explicit HTTP/HTTPS application configuration to startup-only TLS file
  loading, enforce client-certificate/minimum-version policy and preserve routing.
- Keep applications without HTTP configuration free of implicit listeners and
  report bind failures as `EK_HTTP_LISTEN`.
