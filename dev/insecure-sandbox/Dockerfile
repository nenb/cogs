# Non-authoritative Stage 1 functional driver. Never use this image for a VM-isolation claim.
FROM debian:13-slim@sha256:020c0d20b9880058cbe785a9db107156c3c75c2ac944a6aa7ab59f2add76a7bd

ARG DEBIAN_SNAPSHOT=20260713T000000Z
ARG DEBIAN_SECURITY_SNAPSHOT=20260815T000000Z
RUN printf '%s\n' \
      'Types: deb' \
      "URIs: http://snapshot.debian.org/archive/debian/${DEBIAN_SNAPSHOT}/" \
      'Suites: trixie' \
      'Components: main' \
      'Signed-By: /usr/share/keyrings/debian-archive-keyring.gpg' \
      'Check-Valid-Until: no' \
      '' \
      'Types: deb' \
      "URIs: http://snapshot.debian.org/archive/debian-security/${DEBIAN_SECURITY_SNAPSHOT}/" \
      'Suites: trixie-security' \
      'Components: main' \
      'Signed-By: /usr/share/keyrings/debian-archive-keyring.gpg' \
      'Check-Valid-Until: no' \
      > /etc/apt/sources.list.d/debian.sources \
    && apt-get -o APT::Update::Error-Mode=any update \
    && DEBIAN_FRONTEND=noninteractive apt-get install --yes --no-install-recommends \
      bsdutils=1:2.41.5-0+deb13u1 \
      libblkid1=2.41.5-0+deb13u1 \
      liblastlog2-2=2.41.5-0+deb13u1 \
      libmount1=2.41.5-0+deb13u1 \
      libsmartcols1=2.41.5-0+deb13u1 \
      libuuid1=2.41.5-0+deb13u1 \
      login=1:4.16.0-2+really2.41.5-0+deb13u1 \
      mount=2.41.5-0+deb13u1 \
      util-linux=2.41.5-0+deb13u1 \
      bash \
      ca-certificates \
      curl \
      dnsutils \
      git \
      iproute2 \
      iptables \
      libexpat1=2.8.2-1~deb13u1 \
      netcat-openbsd \
      nftables \
      nodejs \
      npm \
      openjdk-21-jre-headless=21.0.12+8-1~deb13u1 \
      openssl \
      openssh-client \
      openssh-server \
      python3 \
      python3-httpx \
      python3-pip \
      python3-requests \
      socat \
    && rm -rf /var/lib/apt/lists/* \
    && rm -f /etc/ssh/ssh_host_*_key /etc/ssh/ssh_host_*_key.pub \
    && mkdir -p /workspace /run/sshd /run/cogs-runtime \
    && chmod 0700 /run/cogs-runtime

COPY dev/insecure-sandbox/sshd_config /etc/ssh/sshd_config
COPY dev/insecure-sandbox/entrypoint.sh /usr/local/bin/cogs-insecure-entrypoint

LABEL org.opencontainers.image.source="https://github.com/nenb/cogs" \
      org.opencontainers.image.licenses="Apache-2.0" \
      dev.cogs.profile="insecure-container" \
      dev.cogs.authority="functional-only" \
      dev.cogs.package-policy="debian-trixie-snapshots-20260713-20260815-insecure-conformance-v3"

EXPOSE 2222
ENTRYPOINT ["/usr/local/bin/cogs-insecure-entrypoint"]
