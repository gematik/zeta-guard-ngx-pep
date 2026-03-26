# AccessToken

## Summary
General error during validation of authorization or DPoP.
The client should acquire new access tokens and retry.

## Examples
- request is missing `authorization DPoP $accessToken` header
- request is missing `dpop` header
- access token is not using alg ES256
- token JWK not found in the PDP issuer's `jwks_uri` indicated in OpenID configuration
  fetched from `$pep_pdp_issuer/.well-known/openid-configuration`
