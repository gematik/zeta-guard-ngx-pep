<img align="right" width="250" height="47" src="docs/img/Gematik_Logo_Flag.png"/> <br/>

# Release Notes ZETA PEP

## Release TODO

## Release 2.0.1

### fixed

- ASL: a full session cache no longer answers new handshakes with HTTP 500 (`ngx_slab_alloc()
  failed: no memory`). Unfinished handshakes now expire (`pep_asl_handshake_ttl`, default 5m,
  previously never), expired entries are cleaned up at least every 10s without holding the
  write lock for a full scan, and a failing insert drops expired entries, tops up with the
  oldest live ones (handshakes before sessions) and retries. The scan for that runs under the
  read lock, removal happens in small chunks.

- ASL: a request for a cid that is not (or no longer) in the session cache, e.g. after cleanup
  or eviction, is answered with `403`/error code 9 `unknown CID` (gemSpec_Krypt A_26924)
  instead of `500`/102 `internal error: missing`, so clients know to run a new handshake. This
  applies to established sessions as well as to the handshake (M3); an expired handshake is
  answered the same way. Clients matching on error code 102 for this case need to be adapted.

- ASL: an M3 carrying the cid of an established session no longer deletes that session.

- DSA-6572-1: the compromised emSign (eMudhra) root CAs are now explicitly
  distrusted in the `pep` and `nginx-ingress` runtime images (ca-certificates is
  upgraded and the emSign roots are removed from the system trust store)
- ASL: the inner request's `Host` header is no longer forwarded on the loopback hop; the outer
  request's `Host` is used instead. The loopback hop targets `127.0.0.1` and never uses a
  proxy (with thanks to Machine Spirits UG)
- ASL: inner request targets are only accepted in origin-form (`/path?query`) and always stay on
  the PEP's own listener; a path like `/http://host/…` no longer redirects the inner request to
  that host (with thanks to Machine Spirits UG)
- PDP/PoPP key cache: fetched keys and discovery documents are used for at most
  `pep_jwks_max_lifetime` (default `24h`) before they are fetched again in full, without
  `If-None-Match`/`If-Modified-Since`. Previously the response's `Cache-Control: max-age`
  alone decided, and every `304` renewed it, so a key set accepted once with a long `max-age`
  and the server's current `ETag` stayed in use until the next restart. Cached keys are also
  dropped when discovery names a different `jwks_uri` than the one they were fetched from, a
  `304` to an unconditional request is treated as a failed fetch, and an oversized `max-age`
  can no longer overflow the grace-period calculation. The cache is held per worker
  process; `nginx -s reload` replaces the workers and thereby purges it

- DSA-6572-1: the compromised emSign (eMudhra) root CAs are now explicitly
distrusted in the `pep` and `nginx-ingress` runtime images (ca-certificates is
upgraded and the emSign roots are removed from the system trust store)
- ASL: the inner request's `Host` header is no longer forwarded on the loopback hop; the outer
  request's `Host` is used instead. The loopback hop targets `127.0.0.1` and never uses a
  proxy (with thanks to Machine Spirits UG)
- ASL: inner request targets are only accepted in origin-form (`/path?query`) and always stay on
  the PEP's own listener; a path like `/http://host/…` no longer redirects the inner request to
  that host (with thanks to Machine Spirits UG)
- **BREAKING** `ossl_hsm`: the provider honours the scheme of `HSM_PROXY_ADDR`. Previously
  every address was dialed in plaintext, `https://` included. `https://` now connects with
  TLS and verifies the proxy's certificate against the configured host name, using the system
  trust store or the CA file named by the new `HSM_PROXY_CA`. `http://` (or no scheme) is only
  accepted for a loopback address; for any other address the provider fails to initialise and
  nginx, when configured with a `store:hsm:` key, does not start.
  `HSM_PROXY_ALLOW_PLAINTEXT=1` restores plaintext to a remote address, for local testing or
  when the link is secured by other means such as a service mesh, and logs a warning at every
  start. A `SignResponse` whose `key_id` is empty or differs from the requested one is
  rejected; HSM proxy implementations must return the `key_id` they signed with. Deployments that configured `https://` need a proxy that
  actually serves TLS; deployments that configured `http://host` must switch to `https://`
  (with thanks to Machine Spirits UG)


### added

- `hsm_sim`: optional TLS. `--tls-cert`/`--tls-key` serve TLS on `--listen`,
  `--tls-client-ca` additionally demands a client certificate (mTLS), and `--plaintext-listen`
  opens a second, plaintext listener for clients without TLS support. All four can be set
  through `HSM_SIM_TLS_CERT`, `HSM_SIM_TLS_KEY`, `HSM_SIM_TLS_CLIENT_CA` and
  `HSM_SIM_PLAINTEXT_LISTEN`. Without them the simulator serves plaintext as before.
- `ossl_hsm`: the provider can authenticate to the HSM proxy with a client certificate
  (mTLS, A_28830). `HSM_PROXY_CLIENT_CERT` and `HSM_PROXY_CLIENT_KEY` name PEM files with the
  certificate (chain) and its private key; they are read once at start and require an
  `https://` address.
- Security KPI for impossible travel (A_25484-03, ZETAP-2296): the "possible attack detected"
  log of an impossible-travel rejection now carries `attackDetection.type="impossible_travel"`
  (CAPEC 560 is shared with other errors), next to `user.roles` (see below) as the breakdown by
  user role. The metric `zeta.impossible_travel_count` gets the attribute `user.roles` with the
  same values. Country and location data are not part of this change.
- A_25484-03: attack-detection logs (`possible attack detected: …`, carrying
  `attackDetection.capecId`) have the new attribute `user.roles` with the value
  `Versicherter`, `Leistungserbringer` or `Unbekannt`, so the security KPIs can be
  broken down by user role. The role is derived from the professionOID of the validated access
  token according to gemSpec_OID: `oid_versicherter` → `Versicherter`; the Berufsgruppen of
  Tab_PKI_402 and the care-providing institutions of Tab_PKI_403 (Praxen, Krankenhäuser,
  Apotheken, Rettungsdienst, Pflege, Heil- und Hilfsmittel, …) → `Leistungserbringer`; any
  other professionOID (e.g. Kostenträger, Leistungserbringerorganisationen, gematik, technical
  roles) → `Unbekannt`. Without a token, or when its validation failed, it is `Unbekannt`
  as well. The professionOID itself is not logged.
- directives `pep_asl_session_cache_size` (default 100m, min 1m, max 16g), `pep_asl_session_ttl`
  (default 24h, capped at the 24h of the ASL protocol) and `pep_asl_handshake_ttl` (default 5m).
  The cache is per pod. TTL changes apply on reload. The ASL certificates, roots and testing
  flag are read when the zone is created: a reload keeps the zone, its sessions and these
  settings, unless the size changed, in which case it starts over with an empty cache.
- metrics `zeta.asl.sessions.handshaking` (part of `sessions.active`),
  `zeta.asl.session_cache.used`/`.size` (bytes), `zeta.asl.session_cache.alloc_failures` and
  `.evictions`; alert on any increase of `alloc_failures`.

### changed

- metric `zeta.asl.sessions.active` keeps its meaning (handshakes + sessions), but is an O(1)
  counter now.
- Helm chart (separate repo): pass the new directives through as values.
- Before performance runs, restart the PEP pod to start with an empty session cache.

## Release 2.0.0

### fixed

- **BREAKING** `ZETA-User-Info.birthdate` is taken from the access token's `birthdate` claim
  (A_26973-03), which the authorization server forwards from the sectoral IDP's id_token when
  the insured person consented. Without the claim the field is absent; a value that is no
  `YYYY-MM-DD` date is dropped with a warning. The interim fixed date (ANFTI2-922) and its
  directive `pep_user_info_birthdate` are removed — nginx no longer starts with a
  configuration that still sets it.
- ASL: don't panic on short M3
- purl and load_dispenser add nonce in dpop-token for token exchange
- in `pep_require_popp off` locations, `popp` headers are now also verfied and forwaded
  as `ZETA-PoPP-Token-Content` if present, given a `pep_popp_issuer` is configured.
- `pep_forward_client_data` set at `http`/`server` level is now inherited by locations
- ASL: session requests shorter than the session overhead are rejected (`BadFormat`)
  instead of underflowing
- ASL: redirects on inner responses are never followed

### changed

- A_25669-01: sensitive headers (authorization, dpop, popp) are no longer forwarded to
  upstreams. This can be disabled, by setting corresponding variables either globally in
  the server block, or on a per-location basis (before `include proxy_headers.conf;`):
  before :
  ```nginx.conf
    http {
        server {
            set $zeta_strip_authorization 0;
            set $zeta_strip_dpop 0;
            set $zeta_strip_popp 0;

            location / {
                set $zeta_strip_authorization 0;
                set $zeta_strip_dpop 0;
                set $zeta_strip_popp 0;

                include proxy_headers.conf;

                proxy_pass "http://…/";
            }
        }
    }
  ```

- A_29850: PoPP errors (`PoPPMissing` 400, `PoPP` and `PoPPInvalidActor` 403) no longer carry
  the header `zeta-error-origin: pep`. They are addressed to the caller, who supplies the PoPP
  token, so the ZETA-Client hands them on instead of re-authenticating.
- ASL: an expired session returns the distinct error `AslSessionExpired`, so the client can
  re-handshake and retry
- Bumps nginx version to 1.31.7
- Bumps nginx-ingress version to 5.7.0
- Bumps rust version to 1.99.1

### added

- A_25669-01: optional `ZETA-Access-Token-Content` upstream header with the full,
  Base64-URL encoded JSON payload of the validated access token
  (`pep_forward_access_token_content on|off`, default off).
- `pep_pdp_url`: optional internal base URL for OIDC discovery and the JWKS fetch.
  `pep_pdp_issuer` stays the trust identity (the expected `iss`), so the PDP can be
  reached over an in-cluster address while tokens keep carrying the public issuer.
  The `jwks_uri` advertised by discovery is rewritten from the issuer prefix onto
  `pep_pdp_url`; a `jwks_uri` outside the issuer is fetched as advertised and logged.
  Unset (default) keeps the previous behaviour.

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
