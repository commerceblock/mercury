FROM rustlang/rust:nightly-stretch AS builder

ARG MERC_MS_TEST_SLOT
ARG MERC_MS_TEST_TOKEN
ARG MERC_DB_USER_TEST
ARG MERC_DB_PASS_TEST
ARG MERC_DB_HOST_TEST
ARG MERC_DB_PORT_TEST
ARG MERC_DB_DATABASE_TEST

ENV MERC_MS_TEST_SLOT=$MERC_MS_TEST_SLOT
ENV MERC_MS_TEST_TOKEN=$MERC_MS_TEST_TOKEN
ENV MERC_DB_USER_TEST=$MERC_DB_USER_TEST
ENV MERC_DB_PASS_TEST=$MERC_DB_PASS_TEST
ENV MERC_DB_HOST_TEST=$MERC_DB_HOST_TEST
ENV MERC_DB_PORT_TEST=$MERC_DB_PORT_TEST
ENV MERC_DB_DATABASE_TEST=$MERC_DB_DATABASE_TEST

COPY . /mercury
WORKDIR /mercury

RUN set -ex \
    && apt update \
    && apt install -y \
        lsb-core \
        software-properties-common \
        apt-transport-https \
        ca-certificates \
    && bash -c "$(wget -O - https://apt.llvm.org/llvm.sh)" \
    && rm -rf /var/lib/apt/lists/*

RUN set -ex \
    && cd server \
    && cargo build --release
    #&& cargo test -j 4 -- --test-threads=4 \
    #&& cargo build --release

ENV MERC_MS_TEST_SLOT=
ENV MERC_MS_TEST_TOKEN=
ENV MERC_DB_USER_TEST=
ENV MERC_DB_PASS_TEST=
ENV MERC_DB_HOST_TEST=
ENV MERC_DB_PORT_TEST=
ENV MERC_DB_DATABASE_TEST=

FROM debian:buster

COPY --from=builder /mercury/target/release/server_exec /usr/local/bin/mercury
COPY ./docker-entrypoint.sh /docker-entrypoint.sh

RUN set -x \
    && apt install -y libssl-dev \
    && rm -rf /var/lib/apt/lists/*

ENTRYPOINT ["/docker-entrypoint.sh"]
