<img align="right" width="250" height="47" src="docs/img/Gematik_Logo_Flag.png"/> <br/>

# ZETA PEP

# system dependencies

You need the following programs:
- rust toolchain
- pkg-config
- C toolchain (clang works best)
- gnu make
- gnupg to verify nginx tarballs
- cargo tools (install with `cargo install --locked …`):
    - [cargo-llvm-cov](https://github.com/taiki-e/cargo-llvm-cov)
    - [mdbook](https://github.com/rust-lang/mdBook)
    - [cargo-nextest](https://github.com/nextest-rs/nextest)

Required C libraries and headers:
- pcre2
- openssl
- zlib
- libclang

(look for "-dev" variants of packages if your distro splits into runtime and development
packages)

Additionally, a basic C build setup, e.g. gcc and gnu make.
The nginx configure script will yell at you when something is missing.

## cloning on Windows

You must set git to preserve line-endings when cloning in Windows, otherwise the docker
build (which always runs in Linux) will fail:

```sh
git config core.autocrlf input
```


# environment

## nginx sources

A nginx source tree is required to build the module, and to run the integration tests.
The `NGINX_VERSION` is configured in `.cargo/config.toml`, but an exported env variable
can override it.

> [!IMPORTANT]
> Once initially, and for every `NGINX_VERSION` change, `cargo xtask configure` must be
> run. This fetches tarballs into `.nginx-cache`, verifies signatures, and configures the
> source tree in `.nginx`. This is built automatically and installed into `./prefix` by
> `build.rs`.

> [!IMPORTANT]
> The current `NGINX_VERSION` is mentioned in `Dockerfile`, `.cargo/config.toml`, and
> `.gitlab-ci.yml`. Keep in sync!
> Additionally, major.minor (e.g. 1.29.x) should match the nginx version used in the
> nginx-ingress base image in `.gitlab-ci.yml`.

`prefix` is set as nginx' prefix, so most paths are relative to that directory,
e.g.:
- nginx will look in ./prefix/conf/nginx.conf instead of /etc/nginx.conf
- "load_module modules/libngx_pep.dev.debug.so;" will load ./prefix/modules/libngx_pep.dev.debug.so
  (which is a symlink that points to the libngx_pep.so built by "cargo module")
- temp files are written to ./prefix/*_temp/
- etc.

`./prefix/sbin/nginx` without arguments starts the server and listens on port 8000 with
the debug variant of the ngx_pep module enabled, and debug logging
(`ngx_log_debug_http!`, etc.) enabled.

`misc/nginx.conf.tpl` is a [TinyTemplate](https://github.com/bheisler/TinyTemplate)
generating the main nginx.conf (for just running `prefix/sbin/nginx`) and test-specific
configs.

## shell/IDE environment
To manage project-specific environment variables the `direnv` tool is used.
When using a JetBrains IDE, the [Direnv Integration](https://plugins.jetbrains.com/plugin/15285-direnv-integration)
plugin is known to work to make the env available during "import" tasks calling cargo.
After installation, go to Settings → Direnv Settings and enable both:
- „Automatically … when the project is opened.”
- „Automatically … before every run/debug.”

`.envrc` loads `.envrc.local` if present (developer-specific, .gitignore'd)

## cargo module — alias to build development module

> [!IMPORTANT]
> `cargo build` on its own will not build a new development module anymore (i.e. the one
> that gets loaded with no-argument `./prefix/sbin/nginx`). The different builds (
> `module` — default features, `module-test` with `its` feature and optional lcov) had
> to be split up due to constant build invalidation.
> To build a dev module and start nginx, you have to use `cargo module && ./prefix/sbin/nginx`
> now (`cargo build` only does a compile-check, and will print a warning).

## integration tests, purl, cargo-nextest

cargo-nextest is a replacement for `cargo test` with a different process model: one process per
test (function).

`.config/nextest.toml` has some useful declarations, most notably a setup-script to
rebuild the nginx module and provision `./prefix` as needed before trying to run
integration tests, as they don't have a direct compile-time dependency on the cdylib
and wouldn't trigger it to rebuild on changes.

Some usage examples:
```sh
    # run everything
    cargo nextest run --workspace
    # only run libasl tests and display stdout even for successful tests
    cargo nextest run -p asl --no-capture
    # only run unit tests
    cargo nextest run --workspace -E '!kind(test)'
    # test (function) name containing access, in the main crate
    cargo nextest run access
```

### running the integration tests

The PEP under test does **not** have to be deployed anywhere: the tests spawn their own nginx
(with the freshly built module), an echo server as upstream, an HSM simulator, an OCSP
responder and a PDP revocation mock, all on localhost. Only the token side is remote: the tests
register a client at a ZETA environment (Keycloak/PDP, realm `zeta-guard`) and exchange
access tokens there. That environment must be reachable and must be the one the local test
nginx trusts as issuer. Note that every run registers a new client on it.

The following environment variables must be set (`TestContext` in `tests/common/mod.rs`
panics with `environment variable not found` otherwise). Put them into `.envrc.local` in the
repo root instead of exporting them by hand, see "Environment file" below:

|env               |meaning                                                                          |example                                            |
|---               |---                                                                              |---                                                |
|IT_HOST           |host of the ZETA environment                                                     |zeta-cd.westeurope.cloudapp.azure.com              |
|IT_AUTH           |base URL of its auth server (Keycloak); registration, nonce and token URLs derive from it|https://zeta-cd.westeurope.cloudapp.azure.com/auth|
|IT_P12            |PKCS#12 file with the SMC-B identity (certificate and key)                       |../smcb.p12                                        |
|IT_P12_PASS       |password of `IT_P12` (get it from 1Password)                                                 |                                                   |
|IT_POPP_P12       |PKCS#12 file with the PoPP signing key                                           |misc/popp-token-Server-Sim-nist-komp61.p12         |
|IT_POPP_P12_PASS  |password of `IT_POPP_P12`                                                        |                                                 |
|IT_POPP_P12_ALIAS |alias of the key inside `IT_POPP_P12`                                            |alias                                              |

(The PoPP values are the ones the load-dispenser uses for `misc/popp-token-Server-Sim-nist-komp61.p12`.)

#### SMC-B keystore

The SMC-B keystore and its password are kept in 1Password. The keystore is a base64-encoded
PKCS#12 (the same format as the `*.b64` files the load-dispenser reads), so decode it to a file
outside the repo. Save the two 1Password values as `../smb_keystore` (base64 text) and
`../smb_keystore_pw` (password), then:

```sh
base64 -d < ../smb_keystore > ../smcb.p12   # note the "<": macOS base64 has no file argument
```

`IT_P12` and `IT_P12_PASS` then go into `.envrc.local` (below). Check that the keystore opens
(should print a TEST-ONLY SMC-B subject):

```sh
openssl pkcs12 -in ../smcb.p12 -passin "pass:$(cat ../smb_keystore_pw)" -nokeys -clcerts | openssl x509 -noout -subject -enddate
```

Don't commit the keystore or the password, neither the base64 nor the decoded file.

#### Environment file

`.envrc.local` is git-ignored, so it is the place for the `IT_*` variables (and the keystore
password) that must not be committed. Use absolute paths, the tests run with the crate root as
working directory:

```sh
# .envrc.local
export IT_HOST=zeta-cd.westeurope.cloudapp.azure.com
export IT_AUTH=https://zeta-cd.westeurope.cloudapp.azure.com/auth
export IT_P12=/path/to/smcb.p12
export IT_P12_PASS="$(cat /path/to/smb_keystore_pw)"
export IT_POPP_P12=/path/to/ngx_pep/misc/popp-token-Server-Sim-nist-komp61.p12
export IT_POPP_P12_PASS=<password>
export IT_POPP_P12_ALIAS=alias
```

With direnv, `.envrc` loads `.envrc.local` automatically (see the direnv note above). Without it,
load the file into the current shell with `set -a; . ./.envrc.local; set +a`.

#### Running

```sh
# with the variables from .envrc.local loaded (see above)

# all integration tests
cargo nextest run -p ngx_pep --test it
# a single one
cargo nextest run -p ngx_pep --test it sending_and_receiving_blocks
```

nextest first runs the setup script (`misc/nextest-setup`), which builds the nginx module and
`ossl_hsm`; the first run takes a while. All nginx instances log to `prefix/test.log`, look there
first when a test fails. The tests bind local ports (see below) and need network access to the
ZETA environment, so they don't work in an environment that blocks either.

The test nginx exports its telemetry (OTLP) to an in-process receiver
(`tests/common/otlp.rs`), so tests can assert on the exported logs and metrics, see
`impossible_travel_exported_via_otlp`.

For easier usage of the `purl` tool, these can also be defined:

|env            |example                                            |
|---            |---                                                |
|PURL_HOST      |zeta-cd.westeurope.cloudapp.azure.com              |
|PURL_AUTH      |https://zeta-cd.westeurope.cloudapp.azure.com/auth |
|PURL_P12       |../smb-keystore.p12                                |
|PURL_P12_PASS  |ichangedit                                         |


Note that `PURL_AUTH` only determines the environment to register the client and
exchange access tokens, the request target for the `curl` and `asl` subcommands can be
different.

In combination with setting `pep_pdp_issuer` and `pep_require_aud` in the
local nginx.conf to the same values as `PURL_AUTH`, one can test a remote client
registration locally. See also `misc/nginx.conf.tpl` and `build.rs` for template logic.

For technical reasons the integration tests spawn multiple nginx processes on unique
ports and with unique temporary directories. The configurations get written to
`prefix/conf/test-{port}.conf` by build.rs. The port range `8003..=8010` is provisioned
like this currently. The "max-threads" semaphore in `.config/nextest.toml` is set to 4, half
the number of ports, because the ports of a test that just finished can stay busy for a
moment.

All logs (nginx access and error logs, stdout, stderr) are merged to a single log file
`prefix/test.log`

In CI, the nginx processes must run as (fake) root to be able to write out coverage data
(as the main build is running as root in a container). The test configs therefore set
`user root;`. This only has an effect when the master is started as root, i.e. not when
running the tests locally. So the following warning can be ignored:

`nginx: [warn] the "user" directive makes sense only if the master process runs with super-user privileges, ignored in …/prefix/conf/test-8004.conf:13`

## local docker build

The docker builds are defined in `./docker-bake.hcl`. The default group will build all
runtime images (except load-dispenser, see below) as ":latest", and load them into the
local docker daemon by default:

```shell
docker bake
# only build pep, e.g.
docker bake pep
# …will build ngx_pep:latest

# bake variables can be overriden with env
TAGS=local,another docker bake pep
# will tag ngx_pep:local and ngx_pep:another
```

Run PEP locally with, e.g.:

```sh
docker run --tty --interactive --rm \
  --publish 8080:8080 \
    ngx_pep:latest
```

NOTE: nginx still needs to be configured (`pep_pdp_issuer`, `pep_require_aud`,
Fachdienst URLs, ASL keys, etc. …).
See `./misc/docker/nginx.conf` for the config file template.

To test TLS via HSM Simulator (see below), uncomment these lines:

```nginx.conf
http {
    # …
    server {
        # …
        listen       8443 ssl;
        # …
        ssl_certificate     "tls.p256.pem";
        ssl_certificate_key "store:hsm:tls.p256";
        # …
    }
}
```

The container can now be run with:

```sh
# on the host
cargo run -p hsm_sim -- --listen 0.0.0.0:50051

# in another terminal
docker run --tty --interactive --rm \
  --publish 8080:8080 \
  --publish 8443:8443 \
  --env HSM_PROXY_ADDR=http://10.0.2.2:50051 \
  --env HSM_PROXY_ALLOW_PLAINTEXT=1 \
    ngx_pep:latest
```

The HSM simulator serves plaintext here, and the provider only connects in plaintext to a
loopback address unless `HSM_PROXY_ALLOW_PLAINTEXT=1` is set; see below for the provider's
settings, and [the hsm-sim README.md](./hsm_sim/README.md) for running the simulator with TLS
and client certificates.

`http://10.0.2.2:50051` must be reachable from within the container. For rootless
docker, this can be achieved by passing the environment variable
`DOCKERD_ROOTLESS_ROOTLESSKIT_DISABLE_HOST_LOOPBACK=false` to the daemon.

See [the hsm-sim README.md](./hsm_sim/README.md) for usage details.

To build the hsm_sim image locally:

```sh
docker bake hsm-sim .
```

Then, you can use that instead of local `cargo run` to start the simulator, but you must
provide arguments:

```sh
docker run --tty --interactive --rm \
  --publish 50051:50051 \
  hsm_sim:latest \
  --listen 0.0.0.0:50051 \
  --keys-dir /etc/hsm_sim/keys

# in another terminal
docker run --tty --interactive --rm \
  --publish 8080:8080 \
  --publish 8443:8443 \
  --env HSM_PROXY_ADDR=http://10.0.2.2:50051 \
  --env HSM_PROXY_ALLOW_PLAINTEXT=1 \
    ngx_pep:latest
```

### load-dispenser build

To build the load-dispenser (loadtest driver) locally, you have to provide a tree with
b64-encoded SMC-B keystores to use as `./keystores`. This can be a symlink, for example
to a `zeta-test-certificates` checkout:

```sh
ln -s ../zeta-test-certificates/keystores .
docker bake load-dispenser
```

## HSM Simulator certificates in nginx

`ssl_certificate` in nginx doesn't support the openssl store API, so we need to provide
actual files containing certificate PEM.

The HSM Simulator is designed so that the cert contents only depend on the keyid, so
`./prefix/conf/tls.p256.pem` can be committed and will work with `store:hsm:tls.p256`.

If any of the cert fields in HSM Simulator changes, or when switching the keyid, cert
files can be re-generated with:

```sh
cargo run -p hsm_sim
# in another terminal
grpcurl -plaintext -d '{"key_id": "tls.p256"}' \
  '[::1]:50051' gematik.zetaguard.hsmproxy.v1.HsmProxyService/GetCertificate \
  | jq -r .certificatePem > prefix/conf/tls.p256.pem
```

## nginx-ingress with ossl_hsm support

To build a `nginx/nginx-ingress` container with installed ossl_hsm provider and the
headers-more module, you can use:

```sh
docker bake nginx-ingress
```

You can then use the `store:hsm:<keyid>` syntax as `ssl_certificate_key`. The ingress
controller doesn't support it natively, so you can't use `ingress.spec.tls`, but must
use a snippet:

```yaml
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  annotations:
    nginx.org/rewrite-target: /
    nginx.org/server-snippets: |
      # no tls: section → no SSL listener otherwise
      listen 443 ssl;listen [::]:443 ssl;

      # /etc/nginx/certs mounted to controllers above
      ssl_certificate "/etc/nginx/certs/tls.p256.cert.pem";
      # invoking ossl_hsm
      ssl_certificate_key "store:hsm:tls.p256";

      if ($scheme = http) {
        return 301 https://$host:443$request_uri;
      }
  name: echo
  namespace: default
spec:
  ingressClassName: nginx
  rules:
  - host: fqdn.internal
    http:
      paths:
      - backend:
          service:
            name: echo
            port:
              name: http
        path: /echo/
        pathType: Prefix
```

The provider is configured through the environment:

|Variable|Meaning|
|---|---|
|`HSM_PROXY_ADDR`|`https://host[:port]` of the HSM proxy (default port 50051). `http://` is only accepted for a loopback address; default `http://[::1]:50051`.|
|`HSM_PROXY_CA`|PEM file with the CA certificate(s) the proxy's certificate must chain to. Unset: the system trust store. `https://` only.|
|`HSM_PROXY_CLIENT_CERT`, `HSM_PROXY_CLIENT_KEY`|PEM files with the certificate (chain) and private key the provider authenticates with (mTLS). Both or neither; `https://` only.|
|`HSM_PROXY_ALLOW_PLAINTEXT`|`1` accepts `http://` to a non-loopback address. The provider then neither encrypts nor authenticates the connection itself: only for local testing, or when something else secures the link, e.g. a service mesh sidecar doing mTLS.|

The proxy's certificate must be valid for the host name in `HSM_PROXY_ADDR`. When the address
asks for plaintext to a remote host the provider does not load, and nginx fails to start if
it is configured with a `store:hsm:` key.

The HSM proxy decides who may use which key. Give the provider a client certificate so the
proxy can tell it apart from anything else that reaches it, and keep network access to the
proxy restricted as well. The files are read once when nginx starts; replacing them takes a
restart, a reload is not enough. Certificates and keys must use RSA, NIST P-256/P-384 or
Ed25519.

For this to work, you must define env `HSM_PROXY_ADDR`, and mount certificate files to
`/etc/nginx/certs`, e.g. with the `oci://ghcr.io/nginx/charts/nginx-ingress` Helm chart:

```yaml
controller:
  image:
    ## The image repository of the Ingress Controller.
    repository: your/nginx-ingress
    ## The tag of the Ingress Controller image. If not specified the appVersion from Chart.yaml is used as a tag.
    tag: your-tag

  ## The additional environment variables to be set on the Ingress Controller pods.
  env:
  - name: HSM_PROXY_ADDR
    value: https://your-hsm:50051

  ## The volumes of the Ingress Controller pods.
  volumes:
  - name: certs
    secret:
      secretName: your-certs

  ## The volumeMounts of the Ingress Controller pods.
  volumeMounts:
  - name: certs
    mountPath: /etc/nginx/certs

  ## Enable custom NGINX configuration snippets in Ingress, VirtualServer, VirtualServerRoute and TransportServer resources.
  enableSnippets: true
```


## License

(C) tech@Spree GmbH, 2026, licensed for gematik GmbH

Apache License, Version 2.0

See the [LICENSE](./LICENSE) for the specific language governing permissions and limitations under the License

## Additional Notes and Disclaimer from gematik GmbH

1. Copyright notice: Each published work result is accompanied by an explicit statement of the license conditions for use. These are regularly typical conditions in connection with open source or free software. Programs described/provided/linked here are free software, unless otherwise stated.
2. Permission notice: Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:
    1. The copyright notice (Item 1) and the permission notice (Item 2) shall be included in all copies or substantial portions of the Software.
    2. The software is provided "as is" without warranty of any kind, either express or implied, including, but not limited to, the warranties of fitness for a particular purpose, merchantability, and/or non-infringement. The authors or copyright holders shall not be liable in any manner whatsoever for any damages or other claims arising from, out of or in connection with the software or the use or other dealings with the software, whether in an action of contract, tort, or otherwise.
    3. We take open source license compliance very seriously. We are always striving to achieve compliance at all times and to improve our processes. If you find any issues or have any suggestions or comments, or if you see any other ways in which we can improve, please reach out to: ospo@gematik.de
3. Please note: Parts of this code may have been generated using AI-supported technology. Please take this into account, especially when troubleshooting, for security analyses and possible adjustments.
