# build PEP module, ossl_hsm, hsm_sim and the book.
FROM build-env AS builder

ARG AZDO_CRATES_MIRROR_URL
ARG NGINX_VERSION
ARG SKIP_TESTS

RUN mkdir -p /usr/src/ngx_pep
WORKDIR /usr/src/ngx_pep

COPY Cargo.toml Cargo.lock /usr/src/ngx_pep/
COPY build.rs /usr/src/ngx_pep/
COPY xtask /usr/src/ngx_pep/xtask
COPY .cargo /usr/src/ngx_pep/.cargo

ARG RUSTC_WRAPPER=""
ARG SCCACHE_REDIS=""
ARG CC=""

RUN \
  --mount=type=secret,id=azdo_pat \
<<-'SH'

  MIRROR=${AZDO_CRATES_MIRROR_URL:-} \
    TOKEN=$(cat /run/secrets/azdo_pat 2>/dev/null) \
    . /usr/local/bin/cargo-env

  cargo xtask configure
SH

COPY src /usr/src/ngx_pep/src
COPY libasl /usr/src/ngx_pep/libasl
COPY purl /usr/src/ngx_pep/purl
COPY book /usr/src/ngx_pep/book
COPY hsm_sim /usr/src/ngx_pep/hsm_sim
COPY ossl_hsm /usr/src/ngx_pep/ossl_hsm
COPY hsm_proto /usr/src/ngx_pep/hsm_proto
COPY misc /usr/src/ngx_pep/misc
COPY tests /usr/src/ngx_pep/tests
COPY .config /usr/src/ngx_pep/.config
COPY prefix/modules /usr/src/ngx_pep/prefix/modules
COPY prefix/html/signed-jwks.txt \
     prefix/html/openid-federation.txt \
     prefix/html/empty.json \
     /usr/src/ngx_pep/prefix/html/
COPY prefix/conf/tls.p256.pem prefix/conf/asl.p256.pem /usr/src/ngx_pep/prefix/conf/
COPY load_dispenser /usr/src/ngx_pep/load_dispenser

# NOTE: cache mounts only helps locally, CI doesn't have a long-lived buildkitd, and
# the contents of cache mounts can't be exported.
RUN \
  --mount=type=cache,target=./target,sharing=locked \
  --mount=type=cache,target=${CARGO_HOME}/registry/index,sharing=locked \
  --mount=type=cache,target=${CARGO_HOME}/registry/cache,sharing=locked \
  --mount=type=cache,target=${CARGO_HOME}/registry/git/db,sharing=locked \
  --mount=type=secret,id=azdo_pat \
  --mount=type=secret,id=it_host \
  --mount=type=secret,id=it_p12 \
  --mount=type=secret,id=it_p12_pass \
<<-'SH'

  if [[ -n ${SCCACHE_REDIS:-} ]]; then
    export CARGO_INCREMENTAL=false
  fi

  MIRROR=${AZDO_CRATES_MIRROR_URL:-} \
    TOKEN=$(cat /run/secrets/azdo_pat 2>/dev/null) \
    . /usr/local/bin/cargo-env

  # integration tests run only when the it_* secrets are provided; without
  # them IT_HOST is empty and we skip the test-kind nextests.
  IT_HOST=$(cat /run/secrets/it_host 2>/dev/null || true)
  export IT_HOST
  if [[ -z $IT_HOST ]]; then
    export NEXTEST_FILTERSET="!kind(test)"
  else
    export NEXTEST_FILTERSET=""
    export IT_AUTH="https://$IT_HOST/auth"
    export IT_P12=/run/secrets/it_p12
    IT_P12_PASS=$(cat /run/secrets/it_p12_pass)
    export IT_P12_PASS
    export IT_POPP_P12=/usr/src/ngx_pep/misc/popp-token-Server-Sim-nist-komp61.p12
    export IT_POPP_P12_ALIAS=alias
    export IT_POPP_P12_PASS=00
  fi

  misc/cargo-build

  mkdir -p /out

  cp -a target/module/release/libngx_pep.so /out/

  cp -a target/release/{libossl_hsm.so,hsm_sim,load_dispenser} /out/
  cp -a book/out /out/book
  cp -a {clippy.json,.pkg-version,ngx_pep.cdx.json} \
    /out/
  # these might not exist (SKIP_TESTS=1)
  cp -a {coverage.lcov,prefix/test.log} /out/ || :

  if [[ -n ${SCCACHE_REDIS:-} ]]; then
    sccache -s
  fi

  for bin in \
    /out/libngx_pep.so \
    /out/libossl_hsm.so \
    /out/hsm_sim \
    /out/load_dispenser; do
    (set +o pipefail; readelf -S "$bin" | grep -q '\.dep-v0') \
      || { printf '%s missing .dep-v0 audit section\n' "$bin" >&2; exit 1; }
  done
  if nm -D --defined-only /out/libngx_pep.so | grep -qw ngx_palloc; then
    printf "Found ngx_palloc in libngx_pep.so, maybe stubs.rs was accidentally compiled in?\n\n" >&2
    exit 1
  fi
SH

FROM scratch
COPY --from=builder /out /
