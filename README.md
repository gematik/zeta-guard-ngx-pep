<img align="right" width="250" height="47" src="docs/img/Gematik_Logo_Flag.png"/> <br/>

# ZETA PEP

# system dependencies

You need the following programs:
- rust toolchain
- pkg-config
- C toolchain (clang works best)
- gnu make
- [cargo-llvm-cov](https://github.com/taiki-e/cargo-llvm-cov)

Required C libraries and headers:
- pcre2
- openssl
- zlib
- libclang

(look for "-dev" variants of packages if your distro splits into runtime and development
packages)

Additionally, a basic C build setup, e.g. gcc and gnu make.
The nginx configure script will yell at you when something is missing.

# environment

To manage project-specific environment variables the `direnv` tool is used.
When using a JetBrains IDE, the [Direnv Integration](https://plugins.jetbrains.com/plugin/15285-direnv-integration)
plugin is known to work to make the env available during "import" tasks calling cargo.
After installation, go to Settings → Direnv Settings and enable both:
- „Automatically … when the project is opened.”
- „Automatically … before every run/debug.”

`.envrc` loads `.envrc.local` if present (developer-specific, .gitignore'd)

## integration tests, purl, cargo-nextest

You should install [cargo-nextest](https://nexte.st/):
e.g. by: `cargo install cargo-nextest`.

This is a replacement for `cargo test` with a different process model: one process per
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
|IT_POPP_P12       |../popp-token-generator/src/main/resources/popp-token-Server-Sim-nist-komp61.p12|
|IT_POPP_P12_ALIAS |alias                                                                           |
|IT_POPP_P12_PASS  |00                                                                              |

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
`prefix/conf/test-{port}.conf` by build.rs. The port range `8003..=8010` is provisioned
like this currently, and the "max-threads" sempahore is set to 8 in
`.config/nextest.toml` accordingly.

For that reason, it can be a bit inconvenient to follow test logs, but a multi-file tail
can help:

`tail -F -n 20 prefix/test-*/logs/*`

In CI, the nginx processes must run as (fake) root to be able to write out coverage data
(as the main build is running as root in a container). The test configs therefore set
`user root;`. This only has an effect when the master is started as root, i.e. not when
running the tests locally. So the following warning can be ignored:
`nginx: [warn] the "user" directive makes sense only if the master process runs with super-user privileges, ignored in …/prefix/conf/test-8004.conf:13`


# nginx

Via nginx-sys' "vendored" feature, a nginx source tree is managed by the nginx-source
crate. ./build.rs additionally calls `make install` in that tree to populate ./prefix
for easier testing.
This directory is set as nginx' prefix, so most paths are relative to that directory,
e.g.:
- nginx will look in ./prefix/conf/nginx.conf instead of /etc/nginx.conf
- "load_module modules/debug/libngx_pep.so;" will load ./prefix/modules/debug/libngx_pep.so
  (which is a symlink that points to the libnx_pep.so built by "cargo build")
- temp files are written to ./prefix/*_temp/
- etc.

`./prefix/sbin/nginx` without arguments starts the server and listens on port 8000 with
the debug variant of the ngx_pep module enabled, and debug logging
(`ngx_log_debug_http!`, etc.) enabled.

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
