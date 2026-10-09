# Python 3.12.15 / Debian bookworm, official multi-platform index inspected 2026-10-06.
# Override only with another reviewed full digest.
ARG PYTHON_IMAGE=python:3.12-slim-bookworm@sha256:34386ef0cb081344d7ec1c103ba398e6e9f64e9ab3a1509accc92a4e24a07258
ARG NODE_IMAGE=node:24-bookworm-slim@sha256:d6aa754f16b3197301076f047b5def2f02ea1dbbc2ca920407d46d7ec7f87b20
ARG RUST_IMAGE=rust:1.98.0-bookworm@sha256:82150a52ec202c1b14d7817e14516c392bb7f5cfebd88f1ed531cb37ebd39922
FROM ${RUST_IMAGE} AS rust-build
RUN apt-get update && apt-get install --no-install-recommends -y libseccomp-dev \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /build
COPY Cargo.toml Cargo.lock build.rs ./
COPY src/ src/
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    CARGO_HTTP_MULTIPLEXING=false cargo build --locked --release \
    && CARGO_HTTP_MULTIPLEXING=false cargo test --locked
FROM ${NODE_IMAGE} AS node
FROM ${PYTHON_IMAGE}
ARG PYTHON_IMAGE
ARG NODE_IMAGE
COPY --from=node /usr/local/ /usr/local/
RUN apt-get update && apt-get install --no-install-recommends -y bash git ripgrep curl libseccomp2 tini ca-certificates build-essential pkg-config libatomic1 libstdc++6 \
    && rm -rf /var/lib/apt/lists/* \
    && groupadd --gid 10001 task && useradd --uid 10001 --gid 10001 --no-create-home --home-dir /workspace/home --shell /bin/bash task
COPY --from=rust-build /build/target/release/agenticsandbox /opt/agenticsandbox/agenticsandbox
COPY runtime/entrypoint.sh /usr/local/bin/agenticsandbox-entrypoint
RUN ln -s /opt/agenticsandbox/agenticsandbox /usr/local/bin/agenticsandbox \
    && agenticsandbox runtime-manifest build --base-image "$PYTHON_IMAGE" --node-image "$NODE_IMAGE" \
    && chmod 0755 /usr/local/bin/agenticsandbox-entrypoint \
    && chmod -R a-w /opt/agenticsandbox \
    && mkdir /workspace
LABEL org.opencontainers.image.title="agentic-container"
ENV PYTHONDONTWRITEBYTECODE=1 AGENTICSANDBOX_STORAGE=persistent DISABLE_AUTOUPDATER=1
ENV PATH="/workspace/harnesses/bin:${PATH}"
USER root
WORKDIR /workspace
ENTRYPOINT ["/usr/bin/tini", "--", "/usr/local/bin/agenticsandbox-entrypoint"]
