# #%L
# ngx_pep
# %%
# (C) tech@Spree GmbH, 2026, licensed for gematik GmbH
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
ARG BASE_IMAGE_BUILD="rust:1.92-slim-bookworm"
# NOTE: must match minor nginx version built against, see: `cargo info nginx-src`
# alpine images might not work well due to musl
ARG BASE_IMAGE="nginx:1.28.1-trixie-otel"
FROM ${BASE_IMAGE_BUILD} AS build-env
ARG AZDO_CRATES_MIRROR_URL=""

# docker
RUN apt-get update && \
  DEBIAN_FRONTEND=noninteractive apt-get install --yes \
    ca-certificates \
    curl \
    && \
  install -m 0755 -d /etc/apt/keyrings && \
  curl -fsSL https://download.docker.com/linux/debian/gpg -o /etc/apt/keyrings/docker.asc && \
  chmod a+r /etc/apt/keyrings/docker.asc && \
  echo \
    "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.asc] https://download.docker.com/linux/debian \
    $(. /etc/os-release && echo "$VERSION_CODENAME") stable" | \
    tee /etc/apt/sources.list.d/docker.list > /dev/null && \
  apt-get update && \
  DEBIAN_FRONTEND=noninteractive apt-get install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin && \
  rm -rf /var/lib/apt/lists/*

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
    pkg-config \
    && \
  rm -rf /var/lib/apt/lists/*

RUN rustup component add clippy llvm-tools-preview

COPY misc/cargo-env /usr/local/bin/cargo-env
COPY misc/cov-env /usr/local/share/cov-env

SHELL ["/bin/bash", "-euo", "pipefail", "-c"]

RUN --mount=type=cache,id=cargo-home,target=/usr/local/cargo-home,sharing=locked \
    --mount=type=secret,id=azdo_pat \
<<-'SH'
  MIRROR=${AZDO_CRATES_MIRROR_URL:-} \
    TOKEN=$(cat /run/secrets/azdo_pat 2>/dev/null) \
    . /usr/local/bin/cargo-env

  export CARGO_HOME=/usr/local/cargo-home
  mkdir -p "$CARGO_HOME"

  printf "!! install cargo-llvm-cov\n\n"
  cargo install cargo-llvm-cov --bins --locked --root /usr/local

  printf "!! install cargo-cyclonedx\n\n"
  cargo install cargo-cyclonedx --bins --locked --root /usr/local

  printf "!! install cargo-nextest\n\n"
  cargo install cargo-nextest --bins --locked --root /usr/local
SH

FROM build-env AS local-build

COPY misc/cargo-build /usr/local/bin/cargo-build

RUN mkdir -p /usr/src/ngx_pep
WORKDIR /usr/src/ngx_pep

COPY sonar-project.properties /usr/src/ngx_pep/
COPY Cargo.toml Cargo.lock /usr/src/ngx_pep/
COPY build.rs /usr/src/ngx_pep/
COPY src /usr/src/ngx_pep/src
COPY libasl /usr/src/ngx_pep/libasl
COPY misc/nginx.conf.tpl /usr/src/ngx_pep/misc/
COPY purl /usr/src/ngx_pep/purl
COPY tests /usr/src/ngx_pep/tests

RUN \
<<-'SH'
  # don't try to run integration tests for local builds
  NEXTEST_FILTERSET="!kind(test)" /usr/local/bin/cargo-build
SH

# gitlab-ci likes to build "locally", copy .so from context
FROM ${BASE_IMAGE} AS ci

COPY misc/docker/nginx.conf /etc/nginx/nginx.conf
COPY misc/docker/default.conf /etc/nginx/conf.d/
COPY target/release/libngx_pep.so /etc/nginx/modules/

# default target, i.e. for interactive usage, copy so. from local-build stage
FROM ${BASE_IMAGE}

COPY misc/docker/nginx.conf /etc/nginx/nginx.conf
COPY misc/docker/default.conf /etc/nginx/conf.d/
COPY --from=local-build /usr/src/ngx_pep/target/release/libngx_pep.so /etc/nginx/modules/
