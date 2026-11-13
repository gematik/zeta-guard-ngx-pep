FROM nginx-ingress

USER root
ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get purge -y \
    nginx-module-image-filter \
    mount \
    && apt-get autoremove -y && apt-get update && apt-get upgrade -y

# DSA-6572-1: eight emSign (eMudhra) intermediate CA keys were compromised.
# The PEP's outbound TLS (reqwest/rustls uses the OS trust store via
# rustls-native-certs) would otherwise trust a forged PoPP service whose
# certificate chains to one of those intermediates. Upgrade ca-certificates and
# explicitly distrust the emSign roots regardless of the version the base image
# still ships.
RUN set -eux; \
    apt-get update; \
    apt-get install --yes --only-upgrade ca-certificates; \
    if [ -f /etc/ca-certificates.conf ]; then \
      sed -i -E '/mozilla\/emSign/ s/^!*/!/' /etc/ca-certificates.conf; \
      rm -f /usr/share/ca-certificates/mozilla/emSign*.crt; \
      update-ca-certificates --fresh; \
    fi; \
    if ls /etc/ssl/certs 2>/dev/null | grep -qiE 'emsign'; then \
      echo 'ERROR: emSign roots still trusted after update-ca-certificates' >&2; \
      exit 1; \
    fi; \
    rm -rf /var/lib/apt/lists/*

# runtime dep for headers-more module
RUN apt-get update\
  && apt-get install -y libpcre2-32-0 \
  && rm -rf /var/lib/apt/lists/*

RUN apt-get purge --allow-remove-essential -y \
    bash \
    liblastlog2-2 \
    libmount1 \
    libsqlite3-0 \
    libuuid1 \
    ncurses-base \
    ncurses-bin \
    perl-base \
    util-linux

USER nginx
