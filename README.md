<img align="right" width="250" height="47" src="docs/img/Gematik_Logo_Flag.png"/> <br/>

# ZETA PEP

# system dependencies

You need the following programs:
- rust toolchain
- pkg-config
- C toolchain
- gnu make
- nodejs

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

To manage project-specific environment variables `.env` is used.
A direnv `.envrc` like the following can be used to ensure they are always up-to-date:

```sh
# optionally source .envrc from parent dir
source_env_if_exists ../.envrc

dotenv
```

## RustRover

Code sync/import fails unless variables in `./.env` are set in Settings→Rust→Environment
variables.
The EnvFile plugin doesn't seem to affect the cargo environment that is used for that
step.
Alternative: set up direnv and run `rustrover .` from the project directory.

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

# test site

`./site` defines a simple test site using keycloak-js to facilitate the PKCE flow in the
dev environment. It is installed automatically by `./build.rs` after installing nginx to
`./prefix` to populate `./prefix/html`.

It needs environment in `./site/.env` which is ignored to allow easy modifications. If
the file doesn't exist, it will be created by copying `./site/.env.tpl`.

On modifications, it can be build and installed with `(cd ./site && npm run build && npm run prefix_install)`.
A dev server is available: `(cd ./site && npm run dev)`

## License

(C) akquinet tech@Spree GmbH, 2025, licensed for gematik GmbH

Apache License, Version 2.0

See the [LICENSE](./LICENSE) for the specific language governing permissions and limitations under the License

## Additional Notes and Disclaimer from gematik GmbH

1. Copyright notice: Each published work result is accompanied by an explicit statement of the license conditions for use. These are regularly typical conditions in connection with open source or free software. Programs described/provided/linked here are free software, unless otherwise stated.
2. Permission notice: Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:
    1. The copyright notice (Item 1) and the permission notice (Item 2) shall be included in all copies or substantial portions of the Software.
    2. The software is provided "as is" without warranty of any kind, either express or implied, including, but not limited to, the warranties of fitness for a particular purpose, merchantability, and/or non-infringement. The authors or copyright holders shall not be liable in any manner whatsoever for any damages or other claims arising from, out of or in connection with the software or the use or other dealings with the software, whether in an action of contract, tort, or otherwise.
    3. We take open source license compliance very seriously. We are always striving to achieve compliance at all times and to improve our processes. If you find any issues or have any suggestions or comments, or if you see any other ways in which we can improve, please reach out to: ospo@gematik.de
3. Please note: Parts of this code may have been generated using AI-supported technology. Please take this into account, especially when troubleshooting, for security analyses and possible adjustments.