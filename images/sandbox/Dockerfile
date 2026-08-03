# Production guest userland for the externally enforced Kata sandbox profile.
# This image supplies no VM, network, storage, or tenant-isolation claim by itself.
FROM --platform=linux/amd64 ubuntu:24.04@sha256:4fbb8e6a8395de5a7550b33509421a2bafbc0aab6c06ba2cef9ebffbc7092d90

SHELL ["/bin/bash", "-euo", "pipefail", "-c"]

# The minimal Noble base has no CA bundle. These two official snapshot artifacts are
# checksum-constrained before their Package/Version/Architecture identities are checked.
# They supply only enough trust to reach Ubuntu's signed snapshot service; the exact same
# direct versions are then configured normally by APT from authenticated InRelease data.
ADD --checksum=sha256:321b30ad5a1c3783cb3d73ae439f824f6d3874d76a93a62f4a984959b490aa7b \
  https://snapshot.ubuntu.com/ubuntu/20260801T000000Z/pool/main/o/openssl/openssl_3.0.13-0ubuntu3.12_amd64.deb \
  /tmp/cogs-bootstrap-openssl.deb
ADD --checksum=sha256:6bac2a01979e210d9eac1d4d56747ec709ea60654744d66705dc3c36e7629e50 \
  https://snapshot.ubuntu.com/ubuntu/20260801T000000Z/pool/main/c/ca-certificates/ca-certificates_20260601~24.04.1_all.deb \
  /tmp/cogs-bootstrap-ca-certificates.deb

RUN test "$(dpkg-deb -f /tmp/cogs-bootstrap-openssl.deb Package)" = openssl \
    && test "$(dpkg-deb -f /tmp/cogs-bootstrap-openssl.deb Version)" = 3.0.13-0ubuntu3.12 \
    && test "$(dpkg-deb -f /tmp/cogs-bootstrap-openssl.deb Architecture)" = amd64 \
    && test "$(dpkg-deb -f /tmp/cogs-bootstrap-ca-certificates.deb Package)" = ca-certificates \
    && test "$(dpkg-deb -f /tmp/cogs-bootstrap-ca-certificates.deb Version)" = '20260601~24.04.1' \
    && test "$(dpkg-deb -f /tmp/cogs-bootstrap-ca-certificates.deb Architecture)" = all \
    && dpkg --unpack /tmp/cogs-bootstrap-openssl.deb /tmp/cogs-bootstrap-ca-certificates.deb \
    && find /usr/share/ca-certificates -type f -name '*.crt' -printf '%P\n' \
      | LC_ALL=C sort > /etc/ca-certificates.conf \
    && update-ca-certificates --fresh \
    && test -s /etc/ssl/certs/ca-certificates.crt

# Snapshot is fixed independently on both official archive stanzas. Apt 2.8 resolves these
# through snapshot.ubuntu.com and authenticates signed Ubuntu InRelease metadata. Retries,
# insecure repositories, unauthenticated packages, and any non-snapshot fallback are closed.
# Requested names and versions are the complete direct package policy.
RUN printf '%s\n' \
      'Types: deb' \
      'URIs: http://archive.ubuntu.com/ubuntu/' \
      'Suites: noble noble-updates' \
      'Components: main universe' \
      'Signed-By: /usr/share/keyrings/ubuntu-archive-keyring.gpg' \
      'Snapshot: 20260801T000000Z' \
      '' \
      'Types: deb' \
      'URIs: http://security.ubuntu.com/ubuntu/' \
      'Suites: noble-security' \
      'Components: main universe' \
      'Signed-By: /usr/share/keyrings/ubuntu-archive-keyring.gpg' \
      'Snapshot: 20260801T000000Z' \
      > /etc/apt/sources.list.d/ubuntu.sources \
    && printf '%s\n' \
      'Acquire::Retries "0";' \
      'Acquire::AllowInsecureRepositories "false";' \
      'Acquire::AllowDowngradeToInsecureRepositories "false";' \
      'APT::Get::AllowUnauthenticated "false";' \
      'APT::Get::Assume-Yes "false";' \
      'APT::Snapshot "20260801T000000Z";' \
      > /etc/apt/apt.conf.d/99cogs-snapshot-policy \
    && apt-get -o APT::Update::Error-Mode=any update \
    && DEBIAN_FRONTEND=noninteractive apt-get install --yes --no-install-recommends \
      bash=5.2.21-2ubuntu4 \
      ca-certificates=20260601~24.04.1 \
      git=1:2.43.0-1ubuntu7.3 \
      openssh-client=1:9.6p1-3ubuntu13.18 \
      openssh-server=1:9.6p1-3ubuntu13.18 \
      openssl=3.0.13-0ubuntu3.12 \
      python3=3.12.3-0ubuntu2.1 \
    && test -z "$(dpkg --audit)" \
    && readonly forbidden_packages=(bind9-dnsutils curl iproute2 iptables netcat-openbsd nftables nodejs npm openjdk-21-jre-headless python3-httpx python3-pip python3-requests socat) \
    && for package in "${forbidden_packages[@]}"; do \
         if [[ "$(dpkg-query -W -f='${db:Status-Status}' "$package" 2> /dev/null || true)" == installed ]]; then \
           printf 'forbidden production package present: %s\n' "$package" >&2; \
           exit 1; \
         fi; \
       done \
    && rm -f /tmp/cogs-bootstrap-*.deb \
    && rm -rf /root/.ssh \
    && rm -f /etc/ssh/ssh_host_* /etc/ssh/sshd_config.d/* \
      /etc/machine-id /var/lib/dbus/machine-id /var/lib/systemd/random-seed \
    && install -d -o root -g root -m 0700 /root /workspace /run/cogs-runtime \
    && install -d -o root -g root -m 0500 /run/cogs-input \
    && install -d -o root -g root -m 0755 /run/sshd /shared /user /usr/local/libexec \
    && install -d -o root -g root -m 0555 /shared/skills /user/skills

COPY --chown=root:root --chmod=0644 images/sandbox/sshd_config /etc/ssh/sshd_config
COPY --chown=root:root --chmod=0755 images/sandbox/entrypoint.sh /usr/local/sbin/cogs-sandbox-entrypoint
COPY --chown=root:root --chmod=0555 images/sandbox/capture-inputs.py /usr/local/libexec/cogs-capture-inputs

LABEL org.opencontainers.image.source="https://github.com/nenb/cogs" \
      org.opencontainers.image.licenses="Apache-2.0" \
      dev.cogs.profile="kata-sandbox-guest" \
      dev.cogs.package-policy="ubuntu-noble-snapshot-20260801-production-core-v1" \
      dev.cogs.isolation-authority="external-runtime-required" \
      dev.cogs.credentials="proxy-capability-only-no-upstream-secrets" \
      dev.cogs.skills-inputs="external-read-only"

USER 0:0
EXPOSE 22
STOPSIGNAL SIGTERM
ENTRYPOINT ["/usr/local/sbin/cogs-sandbox-entrypoint"]
