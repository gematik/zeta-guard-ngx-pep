<img align="right" width="250" height="47" src="docs/img/Gematik_Logo_Flag.png"/> <br/>

# Release Notes ZETA PEP

## Release 1.3.3

### fixed

- harden ASL subrequest target URL handling
  (with thanks to Machine Spirits UG)

## Release 1.3.2

### added

- `ZETA-User-Info` carries a `birthdate` field for insurant tokens (ANFTI2-922 / A_27558):
  DiPag rejects insurant requests without it, but no PDP claim carries a birthdate yet.
  **Interim solution** — for tokens with professionOID `1.2.276.0.76.4.49` (Versicherte) the
  PEP emits the fixed date `1900-01-01`, overridable per environment with
  `pep_user_info_birthdate <YYYY-MM-DD>;` (http level); other client types (SMC-B/LEI) get
  no `birthdate`. An invalid value aborts the nginx start. To be replaced by the real claim
  once the authorization server forwards the sectoral IDP's `birthdate`.

### changed

- Configuration errors now name the offending directive: `conf_handler!` printed the literal
  `` `$name` `` instead of substituting it, so every misconfiguration logged
  ``nginx: [emerg] `$name`: …``. The handler messages lost the directive name they used to
  repeat, and the `on`/`off` and seconds-valued directives now report a consistent
  ``expected `on` or `off`, got "maybe"`` / `invalid seconds value "abc"`.
- `pep_asl_ocsp` with an unparseable responder URL used to panic (`unparseable pep_asl_ocsp`)
  and abort the nginx start; it now fails as a regular `[emerg]` naming the directive.

## Release 1.3.0

### fixed
- DPoP proofs whose embedded `jwk` omits the optional `alg`/`kid`/`use` members are now accepted;
  previously a missing `jwk` `alg` was rejected with HTTP 401. An explicit `jwk` `alg` other than
  `ES256` is still rejected.
- ASL subrequest now sets `Forwarded.for`; the client ip is determined by the same
  mechanism as elsewhere (forwarded → x-forwarded-for → x-real-ip → socket addr)

### added
- Session revocation (ZETAP-1010): with `pep_revocation_url` set, the PEP reports the
  offending access token to the PDP when it detects an impossible-travel violation
  (`ip_address` claim != client ip), and subscribes to the PDP's block list as
  server-sent events — the connect delivers a snapshot, so a reconnect is also the
  reconciliation. Blocked session ids live in a shared memory zone, so every worker
  enforces what one of them learned; requests presenting a blocked `sid` are rejected
  with `401` / `RevokedSession`.
- Metrics for the above: `zeta.session.blocked_count` (sessions added to the block
  list — **replicated across pods, query with `max`, never `sum`**),
  `zeta.blocked_request_count` and `zeta.impossible_travel_count` (both per-request,
  so `sum` is correct).
- Implement otel traces,logs,metrics (ZETAP-907).
  W3C context is used to re-parent inner ASL requests, and forward tracecontext upstream.
  Metrics only cover items that could not be determined from spanmetrics already (e.g.
  upstream time histogram, /ASL→inner timings, etc.).
- if the validation fails, then a header zeta-error-origin: pep is returned.
  A missing header does not imply an error in the service (Fachdienst).
- logging indications of possible attacks. This logs are enriched with capec categorization. (A_25404)

### changed
- Bumps nginx version to 1.31.3
- Bumps nginx-ingress version to 5.5.4
- Bumps rust version to 1.97.1
- Bumps headers more to 0.40
- To fulfill A_25669-01 the authorization, dpop and popp headers are forwarded 
  to the upstream and not overridden by PEP. In future versions this will be configurable.

## Release 1.2.0

### added

- zeta-cause: proxy handling

### changed

- Invalid access token headers (unparseable JWT) now return HTTP 401 instead of HTTP 500 (ZETAP-1003)
- Missing or unsupported `kid`/`alg` in access token header now consistently return HTTP 401
- Bumps nginx version to 1.31.2
- Bumps nginx-ingress version to 5.5
- Bumps rust version to 1.95

### fixed

- PEP now strips all client-supplied ZETA-* request headers it controls (`ZETA-User-Info`, `ZETA-Client-Data`,
  `ZETA-PoPP-Token-Content`, `ZETA-API-Version`) and overwrites them with its own values, instead of aborting with
  HTTP 500 on a conflicting value (A_25669-01)
- PEP now updates the `Forwarded` header (RFC 7239) on the upstream request with its own element
  (`by=_zetapep`/`for`/`host`/`proto`; `host` and `for` emitted as quoted-strings as required). On the plain
  proxy path any existing value is preserved and the element appended; on the ASL path a fresh element is set
  (the inner request's untrusted `Forwarded`/`X-Forwarded-*` are dropped). `for` carries the observed client IP
  (A_28440). (A_28439)

## Release 1.0.1

### added

- pep_forward_client_data config to set, default off. "zeta-client-data" upstream
  header was always set previously (A_26492-02)

### fixed

- rare deadlock and u-a-f under load-test conditions (ngx-tickle 0.2.4)

### changed

- low-level performance optimizations regarding ASL session locks, client body reading,
  tickle coaslescing (ngx-tickle)
- increased max. ASL session cache size to 100MiB

### removed

- pipelining and keep-alive in the internal http client. This hurt performance because
  it introduced locking overhead; it is faster to establish new connections in the
  ASL→internal use-case, and JWK cache didn't need it

## Release 1.0.0

### added:

- nginx-ingress build that has ossl_hsm and can use it to externalize TLS to an HSM
- popp:
    - validate actorId == access_token.sub
    - quarter-based validity can now be configured, relative validity now also takes
      duration strings like "10d"
- hsm_sim:
    - Enable brainpool curves, and remove p521. supported now:
        - Nid::X9_62_PRIME256V1 (key id suffix .p256)
        - Nid::SECP384R1 (.p384)
        - Nid::BRAINPOOL_P256R1 (.bp256)
        - Nid::BRAINPOOL_P384R1 (.bp384)
        - Nid::BRAINPOOL_P512R1 (.bp512)
- ossl_hsm:
    - support all aforementioned curves
- asl:
    - switch to openssl in ASL key generation, to enable HSM signatures via ossl_hsm
- jwk_cache:
    - can do conditional requests when the JWKS server responds with etag or
      last-modified, and respects cache-control max-age to postpone the next refresh
    - will retry once when JWKS refresh fails before removing the JWKS from the cache

### fixed

- hsm_sim:
    - shutdown hang with dead clients
- ossl_hsm:
    - reconnection issue on gRPC connection reset
- popp:
    - missing PoPP token (when required) now returns 400 Bad Request

### changed:

- dependency upgrades:
    - nginx: 1.29.8
    - ngx-tickle: 0.2.1
- jwk_cache:
    - now sets x-forwarded-for to the client IP when JWKS refreshes are triggered by
      unknown kids, to enable ip-based rate-limiting in the remote server

## Release 0.5.1

### added:

- ossl_hsm — an openssl provider that can do TLS on a HSM

## Release 0.5.0

### added:

- provide OCSP stapling for ASL
- implement no-travel enforcement
- support entity statement and signed JWKS for PoPP

### changed:

- updated to latest libcrux version for ASL crypto
- slimmed down the container image some more to decrease attack surface

### fixed:

- case-independent handling of authorization schemes

## Release 0.4.0

### added:

- openvex-based CVE management
- structured errors:
    - ZETA/high-level errors as application/json (schema: zeta-error.yaml)
    - embedded html error pages for long-form descriptions
    - pass errors on the ASL channel as application/cbor to the caller (type: ErrorResponse)
- ASL
    - certificate config (`pep_asl_*` options)
    - /CertData endpoint

### changed:

- switch to custom nginx build to not be constrained by ngx/vendored and to allow usage
  of nginxinc/nginx-unprivileged base images
- dependency upgrades, notable:
    - Rust 1.94.0
    - nginx 1.29.5
    - ngx-tickle 0.2.0
- sync JSON schemas from gematik/zeta for VSDM2-interop
    - client-data.yaml: ZETA-Client-Data upstream header
    - zeta-user-info.yaml: ZETA-User-Info upstream header
- trim unneeded dependencies from prod. images as part of ongoing CVE mitigations

## Release 0.3.0

### added:

- Implement integration test harness with code coverage measurements
  This re-uses client functionality of the purl utility, which has been extracted to the
  new client module. purl is now a subpackage in the workspace due to crate type
  requirements.

### changed:

- Ensure ZETA-API-Version header is set early, so it is always emitted in error cases
- Added default ports for ws (80) and wss (443) for url normalization (relevant for DPoP
  token verification)
- Compile against nginx 1.28.1, upgrade rust to 1.92, and use trixie-based nginx image
  (from bookworm)
- Update client code to extract AdmissionSyntax from SMC-B certificate, pass telematik-id
  to token exchange and provide client-self-assessment, client_statement, and attestation
  challenge (IT, purl)

## Release 0.2.5

### changed:

- full implementation of ASL test mode (see A_26942 and A_26943)

## Release 0.2.4

### added:

- url normalization for htu verification
- added htu verification again
- extracting userdata and clientdata from access token and passing it on to the Fachdienst

### changed:

- minor build and CI changes

## Release 0.2.3

### changed:

- removed htu verification due to problems with the test setup

## Release 0.2.2

### added:

- PoPP token verification

## Release 0.2.1

### added:

- DPoP Verification and enforcement

## Release 0.2.0

### added:

- token verification as per spec
- Passing user and client information onto the Fachdienst via headers
    - **warning** still contains some mock data
- ASL implementation
    - **warning** not ready for production use yet

## Release 0.1.3

### added:

- Prototype of the ZETA PEP added
