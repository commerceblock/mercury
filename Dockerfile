FROM rustlang/rust:nightly-stretch

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

ENTRYPOINT ["/mercury/docker-entrypoint.sh"]
