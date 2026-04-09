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
> The current `NGINX_VERSION` is mentioned in `Dockerfile` (for the local docker build),
> and `.gitlab-ci` for the base images. Keep in sync with `.cargo/config.toml`!

`prefix` is set as nginx' prefix, so most paths are relative to that directory,
e.g.:
- nginx will look in ./prefix/conf/nginx.conf instead of /etc/nginx.conf
- "load_module modules/debug/libngx_pep.so;" will load ./prefix/modules/debug/libngx_pep.so
  (which is a symlink that points to the libnx_pep.so built by "cargo build")
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

To run the integration tests, the following environment variables must be set:

To use the "purl" utility, the following environment variables must be set:

|env               |example                                                                         |
|---               |---                                                                             |
|IT_AUTH           |https://zeta-cd.westeurope.cloudapp.azure.com/auth                              |
|IT_P12            |../smb-keystore.p12                                                             |
|IT_P12_PASS       |ichangedit                                                                      |

For easier usage of the `purl` tool, these can also be defined:

|env           |example                                            |
|---           |---                                                |
|PURL_AUTH     |https://zeta-cd.westeurope.cloudapp.azure.com/auth |
|PURL_P12      |../smb-keystore.p12                                |
|PURL_P12_PASS |ichangedit                                         |


Note that `PURL_AUTH` only determines the environment to register the client and
exchange access tokens, the request target for the `curl` and `asl` subcommands can be
different.

In combination with setting `pep_pdp_issuer` and `pep_require_aud` in the
local nginx.conf to the same values as `PURL_AUTH`, one can test a remote client
registration locally. See also `misc/nginx.conf.tpl` and `build.rs` for template logic.

For technical reasons the integration tests spawn multiple nginx processes on unique
ports and with unique temporary directories. The configurations get written to
`prefix/conf/test-{port}.conf` by build.rs. The port range `8003..=8006` is provisioned
like this currently, and the "max-threads" sempahore is set to 4 in
`.config/nextest.toml` accordingly.

All logs (nginx access and error logs, stdout, stderr) are merged to a single log file
`prefix/test.log`

In CI, the nginx processes must run as (fake) root to be able to write out coverage data
(as the main build is running as root in a container). The test configs therefore set
`user root;`. This only has an effect when the master is started as root, i.e. not when
running the tests locally. So the following warning can be ignored:

`nginx: [warn] the "user" directive makes sense only if the master process runs with super-user privileges, ignored in …/prefix/conf/test-8004.conf:13`

## local docker build

The image can be build locally with:

```sh
docker buildx build -t ngx_pep:local .
```

And run with, e.g.:

```sh
docker run --tty --interactive --rm \
  --publish 8080:8080 \
    ngx_pep:local
```

NOTE: nginx still needs to be configured (`pep_pdp_issuer`, `pep_require_aud`,
Fachdienst URLs, ASL keys, etc. …).
See `./misc/docker/nginx.conf` for the config file template.

To test TLS via HSM Simulator (see below), comment in these lines:

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
    ngx_pep:local
```

`http://10.0.2.2:50051` must be reachable from within the container. For rootless
docker, this can be achieved by passing the environment variable
`DOCKERD_ROOTLESS_ROOTLESSKIT_DISABLE_HOST_LOOPBACK=false` to the daemon.

See [the hsm-sim README.md](./hsm_sim/README.md) for usage details.

To build the hsm_sim image locally:

```sh
docker buildx build -t hsm_sim:local --target hsm-sim .
```

Then, you can use that instead of local `cargo run` to start the simulator, but you must
provide arguments:

```sh
docker run --tty --interactive --rm \
  --publish 50051:50051 \
  hsm_sim:local \
  --listen 0.0.0.0:50051 \
  --keys-dir /etc/hsm_sim/keys

# in another terminal
docker run --tty --interactive --rm \
  --publish 8080:8080 \
  --publish 8443:8443 \
  --env HSM_PROXY_ADDR=http://10.0.2.2:50051 \
    ngx_pep:local
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
