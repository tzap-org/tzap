FROM ghcr.io/cross-rs/aarch64-unknown-linux-musl:0.2.5

RUN apt-get update && apt-get install -y --no-install-recommends python3 ca-certificates perl \
    && rm -rf /var/lib/apt/lists/*
COPY build-openssl.py /tmp/build-openssl.py
RUN python3 /tmp/build-openssl.py --root /opt/tzap-openssl aarch64-unknown-linux-musl

ENV OPENSSL_DIR=/opt/tzap-openssl/aarch64-unknown-linux-musl OPENSSL_NO_VENDOR=1 OPENSSL_STATIC=1
