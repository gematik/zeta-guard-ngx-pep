## headers-more — openresty/headers-more-nginx-module as dynamic module.
FROM build-env AS builder

ARG AZDO_CRATES_MIRROR_URL
ARG NGINX_VERSION
ARG HEADERS_MORE_VERSION

RUN mkdir -p /usr/src/headers-more
WORKDIR /usr/src/headers-more

# use the pep xtask to acquire and configure a nginx source tree
COPY xtask /usr/src/headers-more/xtask/

ADD https://github.com/openresty/headers-more-nginx-module/archive/refs/tags/v$HEADERS_MORE_VERSION.tar.gz /headers-more-nginx-module.tar.gz

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

  tar -xzf /headers-more-nginx-module.tar.gz
  rm /headers-more-nginx-module.tar.gz

  export NGX_CONFIGURE_ARGS=--add-dynamic-module="$PWD/headers-more-nginx-module-$HEADERS_MORE_VERSION"
  cargo run --manifest-path xtask/Cargo.toml -- configure

  (
    cd .nginx
    make install -j"$(nproc)"
  )
  mkdir -p /out
  cp prefix/modules/ngx_http_headers_more_filter_module.so /out/ngx_http_headers_more_filter_module.so

  if [[ -n ${SCCACHE_REDIS:-} ]]; then
    sccache -s
  fi
SH

FROM scratch
COPY --from=builder /out /
