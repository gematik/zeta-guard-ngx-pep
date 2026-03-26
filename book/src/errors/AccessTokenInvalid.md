# AccessTokenInvalid

## Summary
The validation of the authorization token failed. The error message lists the detail.

## Examples
- `iss` claim mismatches configured `pep_pdp_issuer`
- `nbf` after current time
- `iat` after current time (after considering `pep_leeway`, i.e. `(iat - pep_leeway) > now)`
- `aud`/`scope` doesn't match `pep_require_aud`/`pep_require_scope`
