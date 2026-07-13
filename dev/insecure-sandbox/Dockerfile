# Non-authoritative Stage 1 functional driver. Never use this image for a VM-isolation claim.
FROM debian:13-slim@sha256:28de0877c2189802884ccd20f15ee41c203573bd87bb6b883f5f46362d24c5c2

ARG DEBIAN_SNAPSHOT=20260713T000000Z
RUN printf '%s\n' \
      'Types: deb' \
      "URIs: http://snapshot.debian.org/archive/debian/${DEBIAN_SNAPSHOT}/" \
      'Suites: trixie' \
      'Components: main' \
      'Signed-By: /usr/share/keyrings/debian-archive-keyring.gpg' \
      'Check-Valid-Until: no' \
      > /etc/apt/sources.list.d/debian.sources \
    && apt-get -o APT::Update::Error-Mode=any update \
    && DEBIAN_FRONTEND=noninteractive apt-get install --yes --no-install-recommends \
      bash \
      ca-certificates \
      curl \
      dnsutils \
      git \
      iproute2 \
      iptables \
      netcat-openbsd \
      nftables \
      nodejs \
      npm \
      openjdk-21-jre-headless \
      openssh-client \
      openssh-server \
      python3 \
      python3-pip \
      socat \
    && rm -rf /var/lib/apt/lists/* \
    && mkdir -p /workspace /run/sshd /run/cogs-runtime

COPY dev/insecure-sandbox/sshd_config /etc/ssh/sshd_config
COPY dev/insecure-sandbox/entrypoint.sh /usr/local/bin/cogs-insecure-entrypoint

LABEL org.opencontainers.image.source="https://github.com/nenb/cogs" \
      org.opencontainers.image.licenses="Apache-2.0" \
      dev.cogs.profile="insecure-container" \
      dev.cogs.authority="functional-only"

EXPOSE 2222
ENTRYPOINT ["/usr/local/bin/cogs-insecure-entrypoint"]
