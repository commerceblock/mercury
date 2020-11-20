Mercury
=====================================
Mercury is a [statechain](https://github.com/RubenSomsen/rubensomsen.github.io/blob/master/img/statechains.pdf) client/server implementation modified to be compatible with current Bitcoin network technology.

Ownership of deposited Bitcoin (or Elements based) UTXOs can be transferred between parties without performing on-chain transactions. This allows for near instant payments, increased privacy and novation of DLCs/Lightning Channels.

Swaps are a method of performing many off-chain transfers atomically. The number of participants in a swap is unlimited. If `n` participants take part in a swap with one distinct UTXO each they receive back ownership of any one of the `n` UTXOs of the same value. 

This repository contains the Server and Client implementation for the protocol. For more information on the components of Mercury see their respective crates.

You can read the whitepaper [here](doc/statechains.md).

Running / Building
-------

Run steps:
To run the software, use Docker image from DockerHub.

1. Download and start: ```docker run --rm -it -p 8000:8000 commerceblock/mercury server```
2. Test: ```curl -vk localhost:8000/ping```

Build steps:
To build the software use Dockerfile provided.

1. Clone repo
2. Build: ```cd mercury && docker build -t commerceblock/mercury:my_build .```
3. Run: ```docker run --rm -it -p 8000:8000 commerceblock/mercury:my_build server```
4. Test: ```curl -vk localhost:8000/ping```

Tests
-------

To run the tests:
1. ```cargo test```

To run integration tests with a real database - database and mainstay environment variables should be set. See server/README.
1. ```(cd integration-tests && cargo test --no-default-features -- --test-threads=1)```
