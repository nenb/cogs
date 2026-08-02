# Production guest userland for the externally enforced Kata sandbox profile.
# This image supplies no VM, network, storage, or tenant-isolation claim by itself.
FROM debian:13-slim@sha256:020c0d20b9880058cbe785a9db107156c3c75c2ac944a6aa7ab59f2add76a7bd

SHELL ["/bin/bash", "-euo", "pipefail", "-c"]

# Both repositories are immutable snapshots. APT authenticates their signed InRelease
# metadata with the pinned Debian archive keyring; HTTP avoids a circular dependency on
# the newer CA bundle installed from that authenticated snapshot. Requested package names
# and versions are deliberately closed; changing this list is a package-policy change.
RUN printf '%s\n' \
      'Types: deb' \
      'URIs: http://snapshot.debian.org/archive/debian/20260713T000000Z/' \
      'Suites: trixie' \
      'Components: main' \
      'Signed-By: /usr/share/keyrings/debian-archive-keyring.gpg' \
      'Check-Valid-Until: no' \
      '' \
      'Types: deb' \
      'URIs: http://snapshot.debian.org/archive/debian-security/20260731T000000Z/' \
      'Suites: trixie-security' \
      'Components: main' \
      'Signed-By: /usr/share/keyrings/debian-archive-keyring.gpg' \
      'Check-Valid-Until: no' \
      > /etc/apt/sources.list.d/debian.sources \
    && printf '%s\n' \
      'Acquire::Retries "0";' \
      'APT::Get::AllowUnauthenticated "false";' \
      'APT::Get::Assume-Yes "false";' \
      > /etc/apt/apt.conf.d/99cogs-snapshot-policy \
    && apt-get -o APT::Update::Error-Mode=any update \
    && DEBIAN_FRONTEND=noninteractive apt-get install --yes --no-install-recommends \
      bash=5.2.37-2+b9 \
      bind9-dnsutils=1:9.20.26-1~deb13u1 \
      ca-certificates=20250419 \
      curl=8.14.1-2+deb13u4 \
      git=1:2.47.3-0+deb13u1 \
      iproute2=6.15.0-1 \
      iptables=1.8.11-2 \
      libexpat1=2.8.2-1~deb13u1 \
      netcat-openbsd=1.229-1 \
      nftables=1.1.3-1 \
      nodejs=20.19.2+dfsg-1+deb13u2 \
      npm=9.2.0~ds1-3 \
      openjdk-21-jre-headless=21.0.11+10-1~deb13u2 \
      openssh-client=1:10.0p1-7+deb13u4 \
      openssh-server=1:10.0p1-7+deb13u4 \
      openssh-sftp-server=1:10.0p1-7+deb13u4 \
      openssl=3.5.6-1~deb13u2 \
      python3=3.13.5-1 \
      python3-httpx=0.28.1-1 \
      python3-pip=25.1.1+dfsg-1 \
      python3-requests=2.32.3+dfsg-5+deb13u1 \
      socat=1.8.0.3-1 \
    && rm -rf /var/lib/apt/lists/* /root/.ssh \
    && rm -f /etc/ssh/ssh_host_* /etc/ssh/sshd_config.d/* \
      /etc/machine-id /var/lib/dbus/machine-id /var/lib/systemd/random-seed \
    && install -d -o root -g root -m 0700 /root /workspace /run/cogs-runtime \
    && install -d -o root -g root -m 0500 /run/cogs-input \
    && install -d -o root -g root -m 0755 /run/sshd /shared /user \
    && install -d -o root -g root -m 0555 /shared/skills /user/skills

COPY --chown=root:root --chmod=0644 images/sandbox/sshd_config /etc/ssh/sshd_config
COPY --chown=root:root --chmod=0755 images/sandbox/entrypoint.sh /usr/local/sbin/cogs-sandbox-entrypoint

LABEL org.opencontainers.image.source="https://github.com/nenb/cogs" \
      org.opencontainers.image.licenses="Apache-2.0" \
      dev.cogs.profile="kata-sandbox-guest" \
      dev.cogs.package-policy="debian-trixie-snapshots-20260713-20260731-v1" \
      dev.cogs.isolation-authority="external-runtime-required" \
      dev.cogs.credentials="proxy-capability-only-no-upstream-secrets" \
      dev.cogs.skills-inputs="external-read-only"

USER 0:0
EXPOSE 22
STOPSIGNAL SIGTERM
ENTRYPOINT ["/usr/local/sbin/cogs-sandbox-entrypoint"]
