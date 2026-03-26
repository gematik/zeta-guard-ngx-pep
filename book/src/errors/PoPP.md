# PoPP

## Summary
`require_popp` is configured, but the PoPP token could not be validated. The error
detail lists the failing validation steps.

## Examples
- request is missing `popp` header or the token could not be parsed
- `typ != "vnd.telematik.popp+jwt"`
- token JWK not found in the PoPP issuer's `jwks_uri` indicated in OpenID configuration
  fetched from `$pep_popp_issuer/.well-known/openid-configuration`
- token issued in the future (after considering `pep_leeway`, i.e. `(iat - pep_leeway) > now)`
- token expired (`iat + $pep_dpop_validity + $pep_leeway > now`)
