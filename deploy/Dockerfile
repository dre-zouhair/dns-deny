# ─── Build stage ──────────────────────────────────────────────────────────────
FROM rust:1.90-slim AS builder

# Install build dependencies (needed for rusqlite bundled SQLite)
RUN apt-get update && apt-get install -y \
    pkg-config \
    libssl-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /build

# Cache dependency compilation separately from source changes
COPY Cargo.toml Cargo.lock ./
COPY api/Cargo.toml       api/Cargo.toml
COPY core/Cargo.toml      core/Cargo.toml
COPY filter/Cargo.toml    filter/Cargo.toml
COPY ingest/Cargo.toml    ingest/Cargo.toml
COPY logger/Cargo.toml    logger/Cargo.toml
COPY scoring/Cargo.toml   scoring/Cargo.toml
COPY rule_types/Cargo.toml rule_types/Cargo.toml

# Create stub lib/main files so Cargo can resolve the full dependency graph
# and cache the compiled deps layer before we copy real source.
RUN mkdir -p src api/src core/src filter/src ingest/src logger/src scoring/src rule_types/src && \
    echo 'fn main() {}' > src/main.rs && \
    for crate in api core filter ingest logger scoring rule_types; do \
        echo '' > $crate/src/lib.rs; \
    done && \
    # api/Cargo.toml declares this example, so the file must exist for the
    # manifest to parse. Release builds never compile it.
    mkdir -p api/examples && echo 'fn main() {}' > api/examples/web_fixture.rs

# Dashboard only: --build-arg CARGO_BUILD_FLAGS="--no-default-features --features feat-web-ui"
# JSON API only:  --build-arg CARGO_BUILD_FLAGS="--no-default-features --features feat-json-api"
ARG CARGO_BUILD_FLAGS=""
RUN cargo build --release $CARGO_BUILD_FLAGS 2>/dev/null || true
# Remove stub artifacts so real source replaces them
RUN find target/release -name "*.d" -delete

# Copy real source and compile
COPY src/       src/
COPY api/src/   api/src/
COPY api/templates/ api/templates/
COPY core/src/  core/src/
COPY filter/src/ filter/src/
COPY ingest/src/ ingest/src/
COPY logger/src/ logger/src/
COPY scoring/src/ scoring/src/
COPY rule_types/src/ rule_types/src/
COPY config/    config/

# BuildKit's COPY preserves the source files' original mtimes from the
# build context, which are almost always older than the stub build's own
# cargo fingerprint/target timestamps from a couple of steps above. Without
# this, cargo's mtime-based rebuild check can conclude nothing changed and
# silently keep linking the *stub* `fn main() {}` binary into the final
# image instead of recompiling the real source -- producing a binary that
# starts, does nothing, and exits 0 with no output at all.
RUN find src api/src api/templates core/src filter/src ingest/src logger/src scoring/src rule_types/src -type f -exec touch {} +

RUN cargo build --release $CARGO_BUILD_FLAGS

# ─── Runtime stage ────────────────────────────────────────────────────────────
FROM debian:bookworm-slim AS runtime

# Install CA certificates (needed for DoT/DoH upstream TLS)
RUN apt-get update && apt-get install -y \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Create non-root user
RUN groupadd --system dns-deny && \
    useradd  --system --gid dns-deny --no-create-home dns-deny

# Copy binary
COPY --from=builder /build/target/release/dns-deny /usr/local/bin/dns-deny

# Default config and UI location
RUN mkdir -p /etc/dns-deny /var/lib/dns-deny && \
    chown dns-deny:dns-deny /var/lib/dns-deny && \
    chmod 750 /var/lib/dns-deny
COPY config/default.toml /etc/dns-deny/config.toml
# Static assets live outside the /var/lib/dns-deny data volume: a volume
# keeps its first copy of the image's files, so assets inside it would never
# update on rebuild.
COPY static/ /usr/share/dns-deny/static/

USER dns-deny
WORKDIR /var/lib/dns-deny

# DNS port (53 requires --cap-add NET_BIND_SERVICE when running unprivileged)
# For development / non-root: use port 1053 via DNS_PORT env var
EXPOSE 53/udp
EXPOSE 53/tcp
EXPOSE 8080/tcp

ENV DNS_CONFIG=/etc/dns-deny/config.toml
ENV DNS_STATE_DB=/var/lib/dns-deny/state.db
ENV DNS_STATIC_DIR=/usr/share/dns-deny/static
ENV RUST_LOG=dns_deny=info,core_dns=info,filter=warn,logger=info,api=info,ingest=warn

ENTRYPOINT ["/usr/local/bin/dns-deny"]
