# Changelog

## 1.0.3 - 2026-07-10

### Fixed

- Added token-strategy logout handling so JWT logout can revoke persisted refresh tokens, clear session state, and trigger logout success/failure hooks.
- Added refresh-token persistence reads during refresh so revoked or unknown persisted refresh tokens are rejected before issuing new tokens.
- Honored custom JWT verifier hooks for both access and refresh tokens.
- Fixed refresh-token generation to use the refresh-token payload builder instead of the access-token payload builder.
- Added default `jti` generation for refresh tokens so identical minimal payloads still produce unique token strings.
- Made refresh-token rotation work without custom `isLimitReached` or `rotateToken` hooks by using default limit handling and internally generated refresh tokens.

### Changed

- Relaxed token persistence and rotation typings to match the optional hooks supported at runtime.
- Made `SoapAuth.create` generic over application-specific user types.
- Bumped package version to `1.0.3`.

### Tests

- Added regression coverage for JWT logout revocation, persistence-backed refresh revocation, custom verifier hooks, refresh payload generation, refresh token uniqueness, default rotation behavior, and app-specific `SoapAuth.create` user typing.
