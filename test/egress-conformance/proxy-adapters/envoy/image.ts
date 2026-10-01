export const ENVOY_VERSION = "1.38.4";
export const ENVOY_IMAGE_DIGEST = "sha256:b28fbee81528c5b6e8857412e5e0f48ea5baa0199cf73ab611aa7f88a808eba7";
export const ENVOY_IMAGE = `docker.io/envoyproxy/envoy:distroless-v${ENVOY_VERSION}@${ENVOY_IMAGE_DIGEST}`;
