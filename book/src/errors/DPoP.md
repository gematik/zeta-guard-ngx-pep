# DPoP

## Summary
No `dpop` header or the DPoP proof token was invalid.

## Examples
- DPoP `"typ != "dpop+jwt"`, `alg != "ES256"`
- access token binding mismatch — `cnf.jkt` != [thumbprint](https://datatracker.ietf.org/doc/html/rfc7638) of DPoP's `jwk`
- token expired (`iat + pep_dpop_validity + pep_leeway < now`)
- HTTP method of request does not match `htm`
- [normalized](#normalization) HTTP target URI to does not match normalized `htu`

The embedded `jwk` is expected to carry only the mandatory public-key members (for EC:
`kty`, `crv`, `x`, `y`). The optional `alg`, `kid` and `use` members are neither required
nor rejected: a missing `jwk` `alg` is accepted (the proof's protected-header `alg` already
pins `ES256`), while an explicit `jwk` `alg` other than `ES256` is rejected.

## normalization scheme {#normalization}
The request determines its “eigen-URL”, i.e. what would have been the original client
request URI. The host and scheme are determined by looking at the following headers, in
order:
1. `forwarded`, first entry; subfields `proto`, `host` (can optionally include port)
2. `x-forwarded-proto`, `x-forwarded-host`, `x-forwarded-port`, first entry each
3. `host` (can optionally include port)

Both the `htu` claim and “eigen-URL” are then normalized as follows:

1. remove query `?` from the URI
2. lowercase scheme and host
3. remove explicit default port (http: 80, https: 443)

