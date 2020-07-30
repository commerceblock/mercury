FROM rustlang/rust:nightly-stretch

ARG MERC_MS_TEST_SLOT
ARG MERC_MS_TEST_TOKEN
ARG DB_USER_TEST
ARG DB_PASS_TEST
ARG DB_HOST_TEST
ARG DB_PORT_TEST
ARG DB_DATABASE_TEST

ENV MERC_MS_TEST_SLOT=$MERC_MS_TEST_SLOT
ENV MERC_MS_TEST_TOKEN=$MERC_MS_TEST_TOKEN
ENV DB_USER_TEST=$DB_USER_TEST
ENV DB_PASS_TEST=$DB_PASS_TEST
ENV DB_HOST_TEST=$DB_HOST_TEST
ENV DB_PORT_TEST=$DB_PORT_TEST
ENV DB_DATABASE_TEST=$DB_DATABASE_TEST

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
    && cargo test -j 4 -- --test-threads=4 \
    && cargo build --release 

ENV MERC_MS_TEST_SLOT=
ENV MERC_MS_TEST_TOKEN=
ENV DB_USER_TEST=
ENV DB_PASS_TEST=
ENV DB_HOST_TEST=
ENV DB_PORT_TEST=
ENV DB_DATABASE_TEST=

ENTRYPOINT ["/mercury/docker-entrypoint.sh"]
