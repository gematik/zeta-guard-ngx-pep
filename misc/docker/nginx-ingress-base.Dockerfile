FROM nginx-ingress

USER root
ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get purge -y \
    nginx-module-image-filter \
    mount \
    && apt-get autoremove -y && apt-get update && apt-get upgrade -y

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
