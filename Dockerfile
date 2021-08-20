FROM commerceblock/bitcoin:0.20.1 AS bitcoin
FROM rustlang/rust:nightly-stretch AS builder

ARG MERC_MS_TEST_SLOT
ARG MERC_MS_TEST_TOKEN
ARG MERC_DB_USER_W
ARG MERC_DB_PASS_W
ARG MERC_DB_HOST_W
ARG MERC_DB_PORT_W
ARG MERC_DB_DATABASE_W
ARG MERC_DB_USER_R
ARG MERC_DB_PASS_R
ARG MERC_DB_HOST_R
ARG MERC_DB_PORT_R
ARG MERC_DB_DATABASE_R

ENV MERC_MS_TEST_SLOT=$MERC_MS_TEST_SLOT \
    MERC_MS_TEST_TOKEN=$MERC_MS_TEST_TOKEN \
    MERC_DB_USER_W=$MERC_DB_USER_W \
    MERC_DB_PASS_W=$MERC_DB_PASS_W \
    MERC_DB_HOST_W=$MERC_DB_HOST_W \
    MERC_DB_PORT_W=$MERC_DB_PORT_W \
    MERC_DB_DATABASE_W=$MERC_DB_DATABASE_W \
    MERC_DB_USER_R=$MERC_DB_USER_R \
    MERC_DB_PASS_R=$MERC_DB_PASS_R \
    MERC_DB_HOST_R=$MERC_DB_HOST_R \
    MERC_DB_PORT_R=$MERC_DB_PORT_R \
    MERC_DB_DATABASE_R=$MERC_DB_DATABASE_R

ENV BITCOIN_VERSION=0.20.1

COPY . /mercury
WORKDIR /mercury

RUN set -ex \
    && apt update \
    && apt install -y \
        apt-utils \
        lsb-core \
        software-properties-common \
        apt-transport-https \
        ca-certificates \
    && bash -c "$(wget https://apt.llvm.org/llvm.sh && chmod +x llvm.sh && ./llvm.sh 12)" \
    && rm -rf /var/lib/apt/lists/*

COPY --from=bitcoin /opt/bitcoin-${BITCOIN_VERSION}/bin/bitcoin-cli /usr/local/bin/
COPY --from=bitcoin /opt/bitcoin-${BITCOIN_VERSION}/bin/bitcoind /usr/local/bin/
COPY --from=bitcoin /opt/bitcoin-${BITCOIN_VERSION}/bin/bitcoin-tx /usr/local/bin/
COPY --from=bitcoin /opt/bitcoin-${BITCOIN_VERSION}/bin/bitcoin-wallet /usr/local/bin/

RUN set -ex \
    && bitcoind \
        -printtoconsole \
        -rpcuser=mercury \
        -rpcpassword=mercury \
        -rpcallowip=0.0.0.0/0 \
        -rpcport=8332 \
        -server=1 \
        -txindex=1 \
        -prune=0 \
        -regtest=1 \
        -daemon=1 \
    && echo "Warming up" && sleep 3 \
    && bitcoin-cli \
        -rpcuser=mercury \
        -rpcpassword=mercury \
        -rpcconnect=0.0.0.0 \
        -rpcport=8332 \
        getblockchaininfo

RUN set -ex \
    && cd server \
    && cargo test -j 4 -- --test-threads=4 \
    && cargo build --release

ENV MERC_MS_TEST_SLOT=
ENV MERC_MS_TEST_TOKEN=
ENV MERC_DB_USER_W=
ENV MERC_DB_PASS_W=
ENV MERC_DB_HOST_W=
ENV MERC_DB_PORT_W=
ENV MERC_DB_DATABASE_W=
ENV MERC_DB_USER_R=
ENV MERC_DB_PASS_R=
ENV MERC_DB_HOST_R=
ENV MERC_DB_PORT_R=
ENV MERC_DB_DATABASE_R=

FROM debian:buster

COPY --from=builder /mercury/target/release/server_exec /usr/local/bin/mercury
COPY ./docker-entrypoint.sh /docker-entrypoint.sh

RUN set -ex \
    && apt update \
    && apt install -y apt-utils libssl-dev apt-transport-https ca-certificates \
    && update-ca-certificates \
    && rm -rf /var/lib/apt/lists/*

ENTRYPOINT ["/docker-entrypoint.sh"]
