Mercury
=====================================
Mercury is a client/server implementation of a state chain ([whitepaper](doc/statechains.md)).

Building
-------
The current 2P-ECDSA uses library multi-party-ecdsa v0.1.0, which depends on rust-paillier v0.1.0.
You will notice that rust-paillier contains depreciated code and so will not build.
We will eventually update the 2P-ECDSA but for now you must open your local version of the rust-paillier
library (as directed to in the error message) and remove/comment the problem line of code.


Disclaimer
-------
### **USE AT YOUR OWN RISK, we are not responsible for software/hardware and/or any transactional issues that may occur while using Gotham city.**

Project Status
-------
The project is currently work in progress.

Server
-------
RESTful web service exposing APIs for state chain and general wallet functionality. [README](server/README.md)

Client
-------
Basic Bitcoin wallet with client side state chain implementation and:

  - Key HD key derivation and storage
  - View balance and UTXOs
  - Send transactions

[README](client/README.md)


Project Description
-------

### Design Overview

#### ECDSA Keygen and Signing
![ECDSA](misc/ecdsa-illustration.png)
* For details on Threshold Signatures see [Threshold Signatures: The Future of Private Keys](https://medium.com/kzen-networks/threshold-signatures-private-key-the-next-generation-f27b30793b)

#### Cryptographic libraries
* [secp256k1](https://github.com/rust-bitcoin/rust-secp256k1/): Rust language bindings for Bitcoin secp256k1 library.
* [curv](https://github.com/KZen-networks/curv) : basic ECC primitives using secp256k1
* [rust-paillier](https://github.com/mortendahl/rust-paillier): A pure-Rust implementation of the Paillier encryption scheme
* [zk-paillier](https://github.com/KZen-networks/zk-paillier): A collection of zero knowledge proofs using Paillier cryptosystem
* [multi-party-ecdsa](https://github.com/KZen-networks/multi-party-ecdsa): Rust implelemtation of Lindell's Crypto17 paper: [Fast Secure Two-Party ECDSA Signing](https://eprint.iacr.org/2017/552)
* [kms](https://github.com/KZen-networks/kms): Two party key managament system (master keys, 2p-HD, shares rotation) for secp256k1 based two party digital sigantures




### Comperative Performance
The comparison was done on an Intel i9-8950HK (2.9GHz) using localhost for server (no real network). The numbers are mean for 20 runs of 2P-ECDSA KeyGen and 50 runs for 2P-ECDSA Signing. Standard deviation is inconsistent but for both implementations it is order of magnitude smaller than mean value.

|        Implementation         |   Gotham city (this repo)    |    [Unbound](https://github.com/unbound-tech/blockchain-crypto-mpc)       |
|-------------------------------|------------------------|------------------------|
| 2P-ECDSA KeyGen                      |        1.05 s            |      **0.813** s           |
|    2P-ECDSA Signing    |      **0.153** s        |      0.206 s     |


License
-------
Gotham City is released under the terms of the GPL-3.0 license. See [LICENSE](LICENSE) for more information.

Contact
-------
For any questions, feel free to [email us](mailto:github@kzencorp.com).
