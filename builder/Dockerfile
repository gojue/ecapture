FROM ghcr.io/loong64/alpine:3.24 AS ecapture

# The build context contains <architecture>/ecapture from Linux release packages.
ARG TARGETARCH
COPY --chmod=755 ${TARGETARCH}/ecapture /ecapture

ENTRYPOINT ["/ecapture"]
