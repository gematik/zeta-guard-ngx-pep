FROM rust

ARG AZDO_CRATES_MIRROR_URL

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && \
  apt-get dist-upgrade -y \
    && \
  rm -rf /var/lib/apt/lists/*

# docker
RUN apt-get update && \
  apt-get install --yes \
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
  apt-get install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin && \
  rm -rf /var/lib/apt/lists/*

# sonarqube-scanner
RUN apt-get update && \
  apt-get install --yes --no-install-recommends \
    curl \
    git \
    openjdk-21-jdk-headless \
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
  apt-get install --yes --no-install-recommends \
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
ENV CARGO_HOME=/usr/local/cargo-home
ENV PATH="$CARGO_HOME/bin${PATH:+:"$PATH"}"

ARG BINSTALL_VERSION=1.12.3
ADD https://github.com/cargo-bins/cargo-binstall/releases/download/v${BINSTALL_VERSION}/cargo-binstall-x86_64-unknown-linux-musl.tgz /tmp/binstall.tgz
RUN mkdir -p "$CARGO_HOME/bin" && tar -xzf /tmp/binstall.tgz -C "$CARGO_HOME/bin" cargo-binstall && rm /tmp/binstall.tgz

ARG RUSTC_WRAPPER=""
ARG SCCACHE_REDIS=""
ARG CC=""

RUN \
  --mount=type=secret,id=azdo_pat \
<<-'SH'

  if [[ -n ${SCCACHE_REDIS:-} ]]; then
    export CARGO_INCREMENTAL=false
  fi

  MIRROR=${AZDO_CRATES_MIRROR_URL:-} \
    TOKEN=$(cat /run/secrets/azdo_pat 2>/dev/null) \
    . /usr/local/bin/cargo-env

  for pkg in \
    sccache@0.16.0 \
    cargo-llvm-cov@0.8.7 \
    cargo-cyclonedx@0.5.9 \
    cargo-nextest@0.9.138 \
    mdbook@0.5.3 \
    cargo-auditable@0.7.5
  do
    printf "!! install %q\n\n" "$pkg"
    cargo binstall --no-confirm "$pkg"
  done
SH
