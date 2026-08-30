# Non-authoritative Stage 1 functional driver. Never use this image for a VM-isolation claim.
FROM debian:testing-slim@sha256:b21cba5194c0cddc19b41045ceebce11b5413ac40bac7f2410c066b5acb28091

ARG DEBIAN_SNAPSHOT=20260829T000000Z
RUN printf '%s\n' \
      'Types: deb' \
      "URIs: http://snapshot.debian.org/archive/debian/${DEBIAN_SNAPSHOT}/" \
      'Suites: testing' \
      'Components: main' \
      'Signed-By: /usr/share/keyrings/debian-archive-keyring.gpg' \
      'Check-Valid-Until: no' \
      > /etc/apt/sources.list.d/debian.sources \
    && apt-get -o APT::Update::Error-Mode=any update \
    && DEBIAN_FRONTEND=noninteractive apt-get install --yes --no-install-recommends \
      bsdutils=1:2.42.2-2 \
      libblkid1=2.42.2-2 \
      liblastlog2-2=2.42.2-2 \
      libmount1=2.42.2-2 \
      libsmartcols1=2.42.2-2 \
      libuuid1=2.42.2-2 \
      login=1:4.16.0-2+really2.42.2-2 \
      mount=2.42.2-2 \
      util-linux=2.42.2-2 \
      bash \
      ca-certificates \
      curl \
      dnsutils \
      git \
      iproute2 \
      iptables \
      libexpat1=2.8.3-1 \
      libssl3t64=3.6.3-1 \
      netcat-openbsd \
      nftables \
      nodejs \
      npm \
      openjdk-25-jre-headless=25.0.4+7-1 \
      openssl=3.6.3-1 \
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
      dev.cogs.package-policy="debian-testing-snapshot-20260829-insecure-conformance-v4"

EXPOSE 2222
ENTRYPOINT ["/usr/local/bin/cogs-insecure-entrypoint"]
