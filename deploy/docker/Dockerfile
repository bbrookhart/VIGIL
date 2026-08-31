# VIGIL container image.
#
# Distroless and non-root. The runtime stage carries no shell, no package manager and no
# build tooling: a compromised VIGIL process is a high-value foothold, and the cheapest way
# to limit what an attacker can do next is to ship nothing for them to use.

# ---------------------------------------------------------------- build
FROM rust:1.82-slim-bookworm AS build

WORKDIR /src

# Dependency layer first, so a source-only change does not rebuild the world.
COPY Cargo.toml Cargo.lock ./
COPY crates/ crates/
RUN cargo build --release --locked \
      --bin vigil-core --bin vigil-gateway --bin vigil \
 && strip target/release/vigil-core target/release/vigil-gateway target/release/vigil

# ---------------------------------------------------------------- runtime
FROM gcr.io/distroless/cc-debian12:nonroot AS runtime

# 65532 is distroless's `nonroot`. It matches the chart's podSecurityContext, so a mismatch
# between image and manifest cannot make a read-only root filesystem fail at runtime.
USER 65532:65532

COPY --from=build /src/target/release/vigil-core    /usr/local/bin/vigil-core
COPY --from=build /src/target/release/vigil-gateway /usr/local/bin/vigil-gateway
COPY --from=build /src/target/release/vigil         /usr/local/bin/vigil

# Policies are mounted from a ConfigMap in Kubernetes; this copy makes the image runnable
# standalone for local evaluation.
COPY --from=build /src/policies /etc/vigil/policies

EXPOSE 8080 8081

# No shell exists in this image, so the entrypoint is the binary directly — there is no
# `sh -c` wrapper for an attacker to reach.
ENTRYPOINT ["/usr/local/bin/vigil-core"]

LABEL org.opencontainers.image.title="VIGIL" \
      org.opencontainers.image.description="Runtime security for autonomous AI agents" \
      org.opencontainers.image.licenses="Apache-2.0" \
      org.opencontainers.image.source="https://github.com/vigil-security/vigil"
