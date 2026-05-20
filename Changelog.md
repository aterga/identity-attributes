# Changelog

## Next

## 0.4.0

- **Breaking**: Renamed env var `origin` → `frontend_origins`. The new value is comma-separated, so an app served from multiple domains lists each one (e.g. `https://app.icp0.io,https://app.example.com`).
- **Breaking**: `onVerified` callback now receives `{ name : ?Text; email : ?Text; sso : ?Text }`. The new `sso` field is the matched trusted SSO domain when the bundle's name/email came from `sso:<domain>:*` keys, otherwise `null`.
- **Breaking**: Error rename `#OriginNotConfigured` → `#FrontendOriginsNotConfigured`; `#OriginMismatch { expected : Text; got : Text }` → `#FrontendOriginMismatch { expected : [Text]; got : Text }`.
- Added optional env var `trusted_sso_domains` (comma-separated). Bundles with `sso:<domain>:name` / `sso:<domain>:email` keys are accepted iff `<domain>` is listed. Absent or empty means no SSO sources are trusted.
- Added error variants `#UntrustedSsoSource { domain : Text }` and `#MixedSsoSources { ssoKeys : [Text]; otherKeys : [Text] }`.

## 0.3.0

- **Breaking**: Renamed mixin methods to `_internet_identity_sign_in_start` and `_internet_identity_sign_in_finish` (snake_case to align with Internet Identity's wire vocabulary).
- Reshaped the library from a class-based provider (`IdentityAttributesProvider`) into a mixin (`include IdentityAttributes({ onVerified = ... })`).
