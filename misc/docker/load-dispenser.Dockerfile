FROM debian

ENV DEBIAN_FRONTEND=noninteractive

# runtime dependencies
RUN apt-get update && \
  apt-get install --yes --no-install-recommends \
    libssl-dev \
    && \
  rm -rf /var/lib/apt/lists/*

ARG UID=101
ARG GID=101

RUN groupadd --system --gid $GID ld \
  && useradd --system --gid ld --no-create-home --home /nonexistent --comment "ld" --shell /bin/false --uid $UID ld || :

RUN mkdir /app
WORKDIR /app
USER ld

COPY misc/popp-token-Server-Sim-nist-komp61.p12 /app/
COPY --from=keystores . /app/keystores

COPY --from=pep-build /load_dispenser /app/load_dispenser

ENTRYPOINT ["/app/load_dispenser"]
