FROM debian

ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && \
  apt-get install --yes --no-install-recommends \
    libssl-dev \
    && \
  rm -rf /var/lib/apt/lists/*

COPY --from=pep-build /hsm_sim /usr/local/bin/
COPY hsm_sim/keys/ca.key /etc/hsm_sim/keys/
COPY hsm_sim/keys/ca.crt /etc/hsm_sim/keys/

ENTRYPOINT ["hsm_sim"]
CMD ["--listen", "0.0.0.0:50051", "--keys-dir", "/etc/hsm_sim/keys/"]
