# Stage 0 build scaffold only; this is not the production Cogs worker image.
FROM gcr.io/distroless/nodejs22-debian12:nonroot@sha256:13593b7570658e8477de39e2f4a1dd25db2f836d68a0ba771251572d23bb4f8e

LABEL org.opencontainers.image.source="https://github.com/nenb/cogs" \
      org.opencontainers.image.licenses="Apache-2.0" \
      dev.cogs.profile="stage0-scaffold"

USER nonroot
CMD ["--version"]
