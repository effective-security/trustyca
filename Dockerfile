# Container images for trustyca.
#
# The binaries link the PKCS#11 provider of xpki with cgo, so they are not
# static: `make docker-build` builds them into bin/linux in the golang image
# of the Debian release these images run on (trixie), and no image here
# carries a Go toolchain or the module cache.
#
#   runtime  the service image: distroless with glibc, no shell
#   tester   the integration test runner: the CLIs plus bash, curl and jq
#
# Build them with `make docker` and `make docker-tester`.

# ---------------------------------------------------------------------------
# tester: runs tests/integration/tests inside the compose network.
# It needs a shell, so it is not distroless.
# ---------------------------------------------------------------------------
FROM debian:trixie-slim AS tester

LABEL org.opencontainers.image.title="trustyca-tester" \
      org.opencontainers.image.vendor="Effective Security" \
      org.opencontainers.image.source="https://github.com/effective-security/trustyca" \
      org.opencontainers.image.description="Trusty CA integration test runner"

RUN apt-get update \
    && apt-get install -y --no-install-recommends bash ca-certificates curl jq \
    && rm -rf /var/lib/apt/lists/*

ENV TRUSTYCA_DIR=/opt/trustyca
# tests/browser holds the headless xdg-open stand-in that `trustyca auth
# login` runs; it is bind-mounted with the rest of the test scripts
ENV PATH=/opt/trustyca/bin:/opt/trustyca/tests/browser:$PATH

COPY bin/linux/ /opt/trustyca/bin/

WORKDIR /opt/trustyca
ENTRYPOINT ["/bin/bash"]

# ---------------------------------------------------------------------------
# runtime: the service image. This is the default build target.
# ---------------------------------------------------------------------------
FROM gcr.io/distroless/base-debian13:nonroot AS runtime

LABEL org.opencontainers.image.title="trustyca" \
      org.opencontainers.image.vendor="Effective Security" \
      org.opencontainers.image.source="https://github.com/effective-security/trustyca" \
      org.opencontainers.image.description="Trusty CA: multi-tenant Certification Authority service"

ENV TRUSTYCA_DIR=/opt/trustyca
ENV PATH=$PATH:/opt/trustyca/bin

# The migrations run on start-up, so they ship with the binary.
# The configuration and the TLS material are mounted, not part of the image.
COPY bin/linux/ /opt/trustyca/bin/
COPY sql/ /opt/trustyca/sql/

# wfe, backend and aia listeners of etc/dev/trustyca-config.yaml
EXPOSE 8880 8881 8888

USER nonroot:nonroot

ENTRYPOINT ["/opt/trustyca/bin/trustycasvc"]
