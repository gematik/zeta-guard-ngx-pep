FROM nginx

USER root
ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update \
    && apt-get dist-upgrade -y \
    && apt-get autoremove -y \
    && rm -rf /var/lib/apt/lists/*

RUN apt-get purge -y \
    curl \
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
    && apt-get autoremove -y \
    && rm -rf /var/lib/apt/lists/*

# runtime dep for headers-more module
RUN apt-get update\
  && apt-get install -y libpcre2-32-0 \
  && rm -rf /var/lib/apt/lists/*

RUN apt-get purge --allow-remove-essential -y \
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
    util-linux \
    && rm -rf /var/lib/apt/lists/*

USER nginx
