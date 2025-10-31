# Security Notes — JWT integration

- **Strong algorithms only:** the native helper only allows HS256 and HS512. Tokens declaring `alg: none` or unsupported algorithms are rejected before signature checks.
- **Verified structure:** base64url segments are validated, decoded and re-encoded to detect truncation or tampering before signature comparison.
- **Timing-safe signature checks:** comparisons use `crypto.timingSafeEqual` to avoid leaking signature length or early exits.
- **Claim enforcement:** `exp`, `nbf`, `iat`, `iss`, `aud`, and `sub` are validated for type, presence (when expected) and logical correctness. Optional `clockTolerance` and `maxAge` defend against clock drift and replay attacks.
- **Secret management:** `AdvancedTokenManager` forwards its managed secret to JWT helpers, keeping configuration centralized while allowing overrides when explicitly requested.
- **Input validation:** signing rejects non-object payloads and conflicting claims; verification fails fast on malformed headers, payloads or options with invalid types.
