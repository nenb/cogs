# Stage 0 build scaffold only; this is not the production Cogs worker image.
FROM gcr.io/distroless/nodejs22-debian13:nonroot@sha256:773a62fbe24a3f8c8b24b16fd59154627f8b406737bc906f83bf1732bc8907dd

LABEL org.opencontainers.image.source="https://github.com/nenb/cogs" \
      org.opencontainers.image.licenses="Apache-2.0" \
      dev.cogs.profile="stage0-scaffold"

USER nonroot
CMD ["--version"]
