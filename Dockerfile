# syntax=docker/dockerfile:1
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

# *** Dockerfile targets ***
# This Dockerfile can produce multiple artifacts and contains internal intermediate
# steps (for caching purposes and reuse).
# Some of the targets have -ci variants, that are only meant to be used from CI.
#
# The final --targets for interactive usage are:
# - pep — nginxinc/nginx-unprivileged with pep, headers-more, and openssl provider
# - nginx-ingress — nginx/nginx-ingress with headers-more and openssl provider
# - hsm-sim — HSM Simulator
#
# If no --target is passed, pep is built.

ARG BASE_IMAGE_BUILD="rust:1.95-slim-bookworm"
ARG NGINX_VERSION=1.31.3 # NOTE: keep in sync with .cargo/config.toml and .gitlab-ci.yml, and with the nginx contained in BASE_IMAGE_INGRESS (exact version)
ARG HEADERS_MORE_VERSION=0.39 # tag *without v prefix*! (https://github.com/openresty/headers-more-nginx-module/tags)
ARG BASE_IMAGE="nginxinc/nginx-unprivileged:$NGINX_VERSION-trixie-otel"
ARG BASE_IMAGE_HSM_SIM="debian:bookworm"
ARG BASE_IMAGE_INGRESS="nginx/nginx-ingress:5.5@sha256:379143154a02d16e4b7d56ad505636bdf73b2c190825ef023c803958ba5eb57c" # NOTE: keep in sync with .gitlab-ci.yml, contained nginx (1.31.3, controller 5.5.4) must match NGINX_VERSION exactly

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
    gnupg \
    protobuf-compiler \
    libprotobuf-dev \
    && \
  rm -rf /var/lib/apt/lists/*

RUN rustup component add clippy llvm-tools-preview

COPY misc/cargo-env /usr/local/bin/cargo-env
COPY misc/cov-env /usr/local/share/cov-env

SHELL ["/bin/bash", "-euo", "pipefail", "-c"]

RUN --mount=type=cache,id=cargo-home,target=/usr/local/cargo-home,sharing=locked \
    --mount=type=secret,id=azdo_pat \
<<-'SH'
  # build-env

  export CARGO_HOME=/usr/local/cargo-home
  mkdir -p "$CARGO_HOME"

  MIRROR=${AZDO_CRATES_MIRROR_URL:-} \
    TOKEN=$(cat /run/secrets/azdo_pat 2>/dev/null) \
    . /usr/local/bin/cargo-env

  printf "!! install cargo-llvm-cov\n\n"
  cargo install cargo-llvm-cov --bins --locked --root /usr/local

  printf "!! install cargo-cyclonedx\n\n"
  cargo install cargo-cyclonedx --bins --locked --root /usr/local

  printf "!! install cargo-nextest\n\n"
  cargo install cargo-nextest --bins --locked --root /usr/local

  printf "!! install mdbook\n\n"
  cargo install mdbook --bins --locked --root /usr/local
SH

# ***
# *** headers-more — openresty/headers-more-nginx-module as dynamic module ***
# ***

FROM build-env AS headers-more

RUN mkdir -p /usr/src/headers-more
WORKDIR /usr/src/headers-more

# use the pep xtask to acquire and configure a nginx source tree
COPY --exclude=**/target xtask /usr/src/headers-more/xtask/

ARG NGINX_VERSION
ENV NGINX_VERSION="$NGINX_VERSION"
ARG HEADERS_MORE_VERSION
ENV HEADERS_MORE_VERSION="$HEADERS_MORE_VERSION"
ADD https://github.com/openresty/headers-more-nginx-module/archive/refs/tags/v$HEADERS_MORE_VERSION.tar.gz /headers-more-nginx-module.tar.gz
RUN \
  --mount=type=cache,id=build-cache-headers-more,target=build-cache,sharing=locked \
  --mount=type=cache,id=cargo-home,target=/usr/local/cargo-home,sharing=locked \
<<-'SH'

  export CARGO_HOME=/usr/local/cargo-home

  mkdir -p build-cache/{target,nginx-cache,nginx}
  cp -a build-cache/target/. xtask/target
  cp -a build-cache/nginx-cache/. .nginx-cache
  cp -a build-cache/nginx/. .nginx

  tar -xzf /headers-more-nginx-module.tar.gz
  export NGX_CONFIGURE_ARGS=--add-dynamic-module="$PWD/headers-more-nginx-module-$HEADERS_MORE_VERSION"
  cargo run --manifest-path xtask/Cargo.toml -- configure

  (
    cd .nginx
    make install -j"$(nproc)"
  )
  cp prefix/modules/ngx_http_headers_more_filter_module.so /ngx_http_headers_more_filter_module.so

  cp -a xtask/target/. build-cache/target
  cp -a .nginx-cache/. build-cache/nginx-cache
  cp -a .nginx/. build-cache/nginx
SH

# ***
# *** build-pep — build PEP module (interactive) ***
# ***

FROM build-env AS build-pep

COPY misc/cargo-build /usr/local/bin/cargo-build

RUN mkdir -p /usr/src/ngx_pep
WORKDIR /usr/src/ngx_pep

COPY sonar-project.properties /usr/src/ngx_pep/
COPY Cargo.toml Cargo.lock /usr/src/ngx_pep/
COPY build.rs /usr/src/ngx_pep/
COPY src /usr/src/ngx_pep/src
COPY --exclude=**/target libasl /usr/src/ngx_pep/libasl
COPY --exclude=**/target purl /usr/src/ngx_pep/purl
COPY --exclude=**/target xtask /usr/src/ngx_pep/xtask
COPY --exclude=**/target book /usr/src/ngx_pep/book
COPY --exclude=**/target hsm_sim /usr/src/ngx_pep/hsm_sim
COPY --exclude=**/target ossl_hsm /usr/src/ngx_pep/ossl_hsm
COPY hsm_proto /usr/src/ngx_pep/hsm_proto
COPY misc /usr/src/ngx_pep/misc
COPY tests /usr/src/ngx_pep/tests
COPY .cargo /usr/src/ngx_pep/.cargo
COPY .config /usr/src/ngx_pep/.config

ARG NGINX_VERSION
ENV NGINX_VERSION="$NGINX_VERSION"
RUN \
  --mount=type=cache,id=build-cache,target=build-cache,sharing=locked \
  --mount=type=cache,id=cargo-home,target=/usr/local/cargo-home,sharing=locked \
<<-'SH'

  export CARGO_HOME=/usr/local/cargo-home

  mkdir -p build-cache/{target,nginx-cache,nginx}
  cp -a build-cache/target/. target
  cp -a build-cache/nginx-cache/. .nginx-cache
  cp -a build-cache/nginx/. .nginx
  # local build

  # don't try to run integration tests for local builds
  NEXTEST_FILTERSET="!kind(test)" \
    /usr/local/bin/cargo-build

  cp -a target/. build-cache/target
  cp -a .nginx-cache/. build-cache/nginx-cache
  cp -a .nginx/. build-cache/nginx
SH

# ***
# *** pep — PEP base image with some packages removed (for CVEs) ***
# ***
FROM ${BASE_IMAGE} AS pep-base

USER root
RUN apt purge -y \
    libde265-0 \
    libexpat1 \
    libfontconfig1 \
    libgcrypt20 \
    libgd3 \
    libheif1 \
    libheif-plugin-dav1d \
    libheif-plugin-libde265 \
    libnghttp2-14 \
    libtiff6 \
    libxml2 \
    nginx-module-image-filter \
    nginx-module-njs \
    nginx-module-xslt \
    passwd \
    && apt autoremove -y && apt update && apt upgrade -y
RUN apt purge --allow-remove-essential -y \
    apt \
    bash \
    debian-archive-keyring \
    libapt-pkg7.0 \
    liblastlog2-2 \
    liblz4-1 \
    libseccomp2 \
    libsqlite3-0 \
    libudev1 \
    libuuid1 \
    libxxhash0 \
    ncurses-base \
    ncurses-bin \
    perl-base \
    sqv \
    util-linux
USER nginx

# ***
# *** pep — PEP runtime image (interactive) ***
# ***
FROM pep-base AS pep

COPY misc/docker/nginx.conf /etc/nginx/nginx.conf
COPY misc/config/common.conf /etc/nginx
COPY misc/config/server_common.conf /etc/nginx
COPY misc/config/asl.conf /etc/nginx
COPY misc/config/proxy_headers.conf /etc/nginx
RUN  rm /etc/nginx/conf.d/default.conf
COPY prefix/conf/tls.p256.pem /etc/nginx
# COPY libasl/fixtures/signer_cert.pem /etc/nginx
# COPY libasl/fixtures/signer_key.pem /etc/nginx
# COPY libasl/fixtures/issuer_cert.pem /etc/nginx
# COPY libasl/fixtures/roots.json /etc/nginx
COPY --from=build-pep /usr/src/ngx_pep/target/release/libngx_pep.so /etc/nginx/modules/
COPY --from=build-pep /usr/src/ngx_pep/book/out /usr/share/nginx/html/doc
# debian: OPENSSLDIR: "/usr/lib/ssl"
COPY misc/docker/openssl.cnf /usr/lib/ssl/openssl.cnf
# debian: MODULESDIR: "/usr/lib/x86_64-linux-gnu/ossl-modules"
COPY --from=build-pep /usr/src/ngx_pep/target/release/libossl_hsm.so /usr/lib/x86_64-linux-gnu/ossl-modules

COPY --from=headers-more /ngx_http_headers_more_filter_module.so /etc/nginx/modules/

# ***
# *** ci-pep — PEP runtime image (CI) ***
# ***

# gitlab-ci likes to build "local", so there is no ci-build-pep, see .gitlab-ci
FROM pep-base AS ci-pep

COPY misc/docker/nginx.conf /etc/nginx/nginx.conf
RUN  rm /etc/nginx/conf.d/default.conf
COPY misc/config/common.conf /etc/nginx
COPY misc/config/server_common.conf /etc/nginx
COPY misc/config/asl.conf /etc/nginx
COPY misc/config/proxy_headers.conf /etc/nginx
COPY prefix/conf/tls.p256.pem /etc/nginx
# COPY libasl/fixtures/signer_cert.pem /etc/nginx
# COPY libasl/fixtures/signer_key.pem /etc/nginx
# COPY libasl/fixtures/issuer_cert.pem /etc/nginx
# COPY libasl/fixtures/roots.json /etc/nginx
COPY target/release/libngx_pep.so /etc/nginx/modules/
COPY book/out /usr/share/nginx/html/doc
# debian: OPENSSLDIR: "/usr/lib/ssl"
COPY misc/docker/openssl.cnf /usr/lib/ssl/openssl.cnf
# debian: MODULESDIR: "/usr/lib/x86_64-linux-gnu/ossl-modules"
COPY target/release/libossl_hsm.so /usr/lib/x86_64-linux-gnu/ossl-modules

# ***
# *** hsm-sim — HSM Simulator (interactive) ***
# ***

FROM ${BASE_IMAGE_HSM_SIM} AS hsm-sim

RUN apt-get update && \
  DEBIAN_FRONTEND=noninteractive apt-get install --yes --no-install-recommends \
    libssl-dev \
    && \
  rm -rf /var/lib/apt/lists/*

COPY --from=build-pep /usr/src/ngx_pep/target/release/hsm_sim /usr/local/bin/
COPY hsm_sim/keys/ca.key /etc/hsm_sim/keys/
COPY hsm_sim/keys/ca.crt /etc/hsm_sim/keys/

ENTRYPOINT ["hsm_sim"]
CMD ["--listen", "0.0.0.0:50051", "--keys-dir", "/etc/hsm_sim/keys/"]

# ***
# *** ci-hsm-sim — HSM Simulator (CI) ***
# ***

FROM ${BASE_IMAGE_HSM_SIM} AS ci-hsm-sim

# ci build; copy hsm_sim and ca from gitlab build context
RUN apt-get update && \
  DEBIAN_FRONTEND=noninteractive apt-get install --yes --no-install-recommends \
    libssl-dev \
    && \
  rm -rf /var/lib/apt/lists/*

COPY target/release/hsm_sim /usr/local/bin/
COPY hsm_sim/keys/ca.key /etc/hsm_sim/keys/
COPY hsm_sim/keys/ca.crt /etc/hsm_sim/keys/

ENTRYPOINT ["hsm_sim"]
CMD ["--listen", "0.0.0.0:50051", "--keys-dir", "/etc/hsm_sim/keys/"]

# ***
# *** nginx-ingress-base — nginx-ingress with some packages removed (for CVEs) ***
# ***

FROM ${BASE_IMAGE_INGRESS} AS nginx-ingress-base
USER root
RUN apt purge -y \
    nginx-module-image-filter \
    perl \
    mount \
    && apt autoremove -y && apt update && apt upgrade -y
RUN apt purge --allow-remove-essential -y \
    bash \
    liblastlog2-2 \
    libmount1 \
    libuuid1 \
    ncurses-base \
    ncurses-bin \
    perl-base \
    util-linux

USER nginx

# ***
# *** nginx-ingress — nginx-ingress with headers-more and ossl_hsm (interactive) ***
# ***

FROM nginx-ingress-base AS nginx-ingress

# debian: OPENSSLDIR: "/usr/lib/ssl"
COPY misc/docker/openssl.cnf /usr/lib/ssl/openssl.cnf
# debian: MODULESDIR: "/usr/lib/x86_64-linux-gnu/ossl-modules"
COPY --from=build-pep /usr/src/ngx_pep/target/release/libossl_hsm.so \
  /usr/lib/x86_64-linux-gnu/ossl-modules/libossl_hsm.so

COPY --from=headers-more /ngx_http_headers_more_filter_module.so /etc/nginx/modules/

# ***
# *** ci-nginx-ingress — nginx-ingress with headers-more and ossl_hsm (CI) ***
# ***

FROM nginx-ingress-base AS ci-nginx-ingress

# debian: OPENSSLDIR: "/usr/lib/ssl"
COPY misc/docker/openssl.cnf /usr/lib/ssl/openssl.cnf
# debian: MODULESDIR: "/usr/lib/x86_64-linux-gnu/ossl-modules"
COPY target/release/libossl_hsm.so /usr/lib/x86_64-linux-gnu/ossl-modules/libossl_hsm.so

COPY --from=headers-more /ngx_http_headers_more_filter_module.so /etc/nginx/modules/

# ***
# *** (default) — alias for pep (interactive) ***
# ***
FROM pep
