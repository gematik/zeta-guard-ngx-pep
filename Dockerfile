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
ARG BASE_IMAGE_BUILD="rust:1.91-slim-bookworm"
# NOTE: must match minor nginx version built against, see: `cargo info nginx-src`
# alpine images might not work well due to musl
ARG BASE_IMAGE="nginx:1.28-bookworm-otel"
FROM ${BASE_IMAGE_BUILD} AS prereqs
ARG AZDO_CRATES_MIRROR_URL=""

ENV CARGO_HOME=/usr/local/cargo-home \
    CARGO_TERM_COLOR=always

# sonarqube-scanner
RUN apt-get update && \
  DEBIAN_FRONTEND=noninteractive apt-get install --yes --no-install-recommends \
    curl \
    git \
    openjdk-17-jdk-headless \
    unzip \
    jq \
    && \
  rm -rf /var/lib/apt/lists/*

ADD "https://binaries.sonarsource.com/Distribution/sonar-scanner-cli/sonar-scanner-cli-7.3.0.5189.zip" /tmp/ss.zip
RUN unzip /tmp/ss.zip -d /tmp/ss \
  && mv /tmp/ss/*/bin/* /usr/local/bin \
  && mv /tmp/ss/*/lib/* /usr/local/lib \
  && rm /tmp/ss.zip

# build dependencies
RUN apt-get update && \
  DEBIAN_FRONTEND=noninteractive apt-get install --yes --no-install-recommends \
    clang \
    libclang-dev \
    libpcre2-dev \
    libssl-dev \
    make \
    zlib1g-dev \
    && \
  rm -rf /var/lib/apt/lists/*

RUN rustup component add clippy llvm-tools-preview

SHELL ["/bin/bash", "-euo", "pipefail", "-c"]


RUN --mount=type=cache,target=/usr/local/cargo-home,sharing=locked \
<<-'SH'
  if [[ -n ${AZDO_CRATES_MIRROR_URL:-} ]]; then
    printf "!! configure crates mirror %q\n\n" "$AZDO_CRATES_MIRROR_URL"

    mkdir -p "$CARGO_HOME"
    cat >"$CARGO_HOME/config.toml" <<-CONFIG
			[registry]
			global-credential-providers = ["cargo:token"]
	
			[registries.crates_mirror]
			index = "$AZDO_CRATES_MIRROR_URL"
	
			[source.crates-io]
			replace-with = "crates_mirror"
CONFIG
  else
    # cargo home is cached
    printf "!! no AZDO_CRATES_MIRROR_URL, removing %s/config.toml\n\n" "$CARGO_HOME/config.toml"
    rm "$CARGO_HOME/config.toml" || :
  fi
SH

RUN --mount=type=cache,target=/usr/local/cargo-home,sharing=locked \
    --mount=type=secret,id=azdo_pat \
<<-'SH'
  if [[ -f /run/secrets/azdo_pat ]]; then
    CARGO_REGISTRIES_CRATES_MIRROR_TOKEN="Basic $(printf "PAT:%s" "$(cat /run/secrets/azdo_pat)" | base64 -w0)"
    export CARGO_REGISTRIES_CRATES_MIRROR_TOKEN
  fi

  printf "!! install cargo-llvm-cov\n\n"

  cargo install cargo-llvm-cov --bins --locked --root /usr/local

  printf "!! install cargo-cyclonedx\n\n"
  cargo install cargo-cyclonedx --bins --locked --root /usr/local
SH

FROM prereqs AS build

COPY sonar-project.properties /usr/src/ngx_pep/
COPY Cargo.toml Cargo.lock /usr/src/ngx_pep/
COPY build.rs /usr/src/ngx_pep/
COPY src /usr/src/ngx_pep/src
COPY libasl /usr/src/ngx_pep/libasl

WORKDIR /usr/src/ngx_pep

RUN --mount=type=cache,target=/usr/local/cargo-home,sharing=locked \
    --mount=type=secret,id=azdo_pat \
<<-'SH'
  if [[ -f /run/secrets/azdo_pat ]]; then
    CARGO_REGISTRIES_CRATES_MIRROR_TOKEN="Basic $(printf "PAT:%s" "$(cat /run/secrets/azdo_pat)" | base64 -w0)"
    export CARGO_REGISTRIES_CRATES_MIRROR_TOKEN
  fi

  echo "--- AAA ---"
  find /usr/local/bin
  type -a cargo-cyclonedx || :
  type -a cargo-llvm-cov || :
  echo "--- /AAA ---"

  printf "!! cargo fetch\n\n"
  cargo fetch --locked

  common_args=(
    --frozen
    # exclude "devel"
    --no-default-features
  )

  printf "!! cargo build\n\n"
  cargo build "${common_args[@]}" --release --lib

  printf "!! clippy\n\n"
  cargo clippy "${common_args[@]}" --release --lib

  printf "!! clippy json\n\n"
  cargo clippy "${common_args[@]}" --release --lib --message-format json > clippy.json

  printf "!! tests\n\n"
  RUST_BACKTRACE=1 cargo llvm-cov --lib "${common_args[@]}" || :

  printf "!! code coverage\n\n"
  cargo llvm-cov "${common_args[@]}" \
    report --lcov --output-path target/llvm-cov-target/coverage.lcov || :

  printf "!! write .pkg-version\n\n"
  cargo metadata --format-version 1 | jq -r '.packages | map(select(.name == "ngx_pep")) | .[0].version' \
    >.pkg-version || :
SH

FROM ${BASE_IMAGE}

COPY docker/nginx.conf /etc/nginx/nginx.conf
COPY docker/default.conf /etc/nginx/conf.d/
COPY --from=build /usr/src/ngx_pep/target/release/libngx_pep.so /etc/nginx/modules/
