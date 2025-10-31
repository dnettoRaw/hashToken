# Security Notes — Native JWT Support

## Threats Addressed
- **Algorithm confusion / `alg: none`** — verification rejects unsigned tokens and enforces explicit algorithm lists.
- **Signature tampering** — signatures recalculated with Node.js `crypto` and compared via `crypto.timingSafeEqual` to block timing attacks.
- **Invalid claims** — numeric date claims (`exp`, `nbf`, `iat`) validated for type and chronology with optional `clockTolerance` and `maxAge` checks.
- **Audience / issuer spoofing** — `aud`, `iss`, and `sub` must match caller expectations and are validated for correct types.
- **Malformed tokens** — strict Base64URL parsing prevents padding or character abuses, and headers/payloads must be JSON objects.

## Defensive Defaults
- HS256 is the default algorithm; HS512 available when explicitly requested.
- `signJwt` auto-populates `iat` and ensures any generated `exp`/`nbf` values derive from it.
- Verification requires a non-empty secret and rejects empty token parts.
- Optional `maxAge` ensures short-lived tokens even when `exp` is missing.

## Operational Guidance
- Store JWT secrets with the same rigor as existing HMAC secrets and rotate regularly.
- Prefer `clockTolerance` values ≤30s to balance resiliency and security.
- Audit consumers to ensure they provide expected `issuer`, `audience`, and `subject` whenever applicable.
- Tests cover altered headers, payload corruption, and claim misuse to guard against regressions.
