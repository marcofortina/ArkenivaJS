# Changelog

## 0.1.0

- Capture native request cancellation before active admission; reject executable or forged signal metadata without running supplied hooks or leaking active requests.
- Keep IPv4 and IPv6 destination blocklists separate so mapped-address exclusions cannot reject public IPv4 destinations; preserve private, reserved and mapped-address rejection before credentials or connection acquisition.

- Add explicit outbound destination policy, bounded responses, cancellation and safe retries over Undici.
