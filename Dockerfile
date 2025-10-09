# #%L
# ngx_pep
# %%
# (C) akquinet tech@Spree GmbH, 2025, licensed for gematik GmbH
# %%
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
# *******
#
# For additional notes and disclaimer from gematik and in case of changes by gematik find details in the "Readme" file.
# #L%
ARG BASE_IMAGE_BUILD="rust:1.89-slim-bookworm"
# NOTE: must match minor nginx version built against, see: `cargo info nginx-src`
# alpine images might not work well due to musl
ARG BASE_IMAGE="nginx:1.28-bookworm"
FROM ${BASE_IMAGE_BUILD} AS build
ARG AZDO_CRATES_MIRROR_URL=""
ARG AZDO_CRATES_PAT=""

ENV CARGO_HOME=/usr/local/cargo \
    CARGO_TERM_COLOR=always

RUN apt-get update && \
  DEBIAN_FRONTEND=noninteractive apt-get install --yes --no-install-recommends \
    make \
    libclang-dev \
    libpcre2-dev \
    libssl-dev \
    zlib1g-dev \
    && \
  rm -rf /var/lib/apt/lists/*

ADD Cargo.toml Cargo.lock .env /usr/src/ngx_pep/
ADD src /usr/src/ngx_pep/src

WORKDIR /usr/src/ngx_pep

SHELL ["/bin/bash", "-euo", "pipefail", "-c"]

RUN --mount=type=cache,target=/usr/local/cargo/registry,sharing=locked \
    --mount=type=cache,target=/usr/local/cargo/git/db,sharing=locked \
    --mount=type=secret,id=azdo_pat \
<<-'SH'
  set -a; . .env; set +a
  if [[ -n ${AZDO_CRATES_MIRROR_URL:-} ]] && [[ -f /run/secrets/azdo_pat ]]; then
    # use secret to make sure it doesn't end up in metadata
    AZDO_CRATES_PAT="$(cat /run/secrets/azdo_pat)"
    export CARGO_REGISTRIES_CRATES_MIRROR_TOKEN="Basic $(printf 'PAT:%s' "${AZDO_CRATES_PAT}" | base64 -w0)"
    export CARGO_REGISTRIES_CRATES_MIRROR_INDEX=${AZDO_CRATES_MIRROR_URL:-}
    printf "Using AZDO crates mirror %s\n\n" "$AZDO_CRATES_MIRROR_URL"

    set -- --config 'registry.global-credential-providers=["cargo:token"]' \
      --config 'source.crates-io.replace-with="crates_mirror"'
  fi
  cargo build --release "$@"
SH

FROM ${BASE_IMAGE}

ADD docker/nginx.conf /etc/nginx/nginx.conf
ADD docker/default.conf /etc/nginx/conf.d/
COPY --from=build /usr/src/ngx_pep/target/release/libngx_pep.so /etc/nginx/modules/
