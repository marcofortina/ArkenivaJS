# Changelog

## 0.1.0

- Capture provider methods without evaluating callable metadata; reject proxy
  callbacks and unbounded prototype traversal before reset authorization or persistence.
- Add bounded native Argon2id hashing, verification, rehash checks and
  distributed attempt budgets.
- Add one-use reset credentials with mandatory atomic application persistence
  for reset consumption, password replacement and session invalidation.
- Add a breach-provider port exposing only a k-anonymity prefix, strict input
  validation and credential-free diagnostic exports.
