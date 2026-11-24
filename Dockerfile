# Modified from https://github.com/external-secrets/external-secrets by NAVER Cloud Corp.

# Pinned release: gcr.io/distroless/static-debian13:latest (Distroless static; Debian 13)
FROM gcr.io/distroless/static@sha256:034df5c1737e8241f6ed6423a12e720ee0f6d6f088609ee172f98f6f2166ef5d

# Add metadata
LABEL maintainer="NAVER Cloud NKS Team" \
      description="External Secrets Operator with the NAVER Cloud Secret Manager provider (fork of external-secrets/external-secrets)"

ARG TARGETOS
ARG TARGETARCH
COPY bin/external-secrets-${TARGETOS}-${TARGETARCH} /bin/external-secrets

# Run as UID for nobody
USER 65534

ENTRYPOINT ["/bin/external-secrets"]
