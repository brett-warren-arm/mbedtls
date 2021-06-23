Mbed TLS - Experimental branch
==============================

# Introduction

This is the experimental branch of [Mbed TLS](https://github.com/armmbed/mbedtls). For more information on Mbed TLS in
general, please see the corresponding
[README.md](https://github.com/armmbed/mbedtls/tree/development/README.md). This readme focuses on the specifics of the experimental branch.

This branch hosts the development of experimental and exploratory features of Mbed TLS. Most of the
development happening here is intended to be upstreamed to main Mbed TLS, but might not yet have reached
the necessary level of code quality and/or testing and/or documentation.

## Feedback and Contribution

If you are interested in trying out or contributing to the features that are being developed here, please reach out! We
welcome any feedback and support, and it will accelerate the process of getting the features in a production ready state
suitable for upstreaming to Mbed TLS' `development` branch.

If you want to share any feedback, just open an issue. If you've made an improvement, open a PR. And if you
have questions of any kind, drop us a line - the main points of contacts are [@hanno-arm](https://github.com/hanno-arm)
and [@hannestschofenig](https://github.com/hannestschofenig).

# Experimental Features

In the following, we describe the features that are currently under development.

## TLS 1.3

## Towards DTLS 1.3, QUIC, cTLS, and Post-Quantum Cryptography: A new Message Processing Stack (MPS)

A growing number of TLS-variants are currently in development, such as DTLS 1.3, QUIC, cTLS, or KemTLS. Some of those
variants maintain the handshake logic of TLS but change lower level details (e.g. QUIC, cTLS, DTLS 1.3), while others
keep the lower layers and change the handshake logic (e.g. KemTLS).

In order to eventually support the large number of TLS-variants with a minimal code base with maximal code sharing, we
have developed a complete rewrite of Mbed TLS' messaging layer, called _Message Processing Stack_ (MPS). MPS provides a
multiple abstraction boundariies between low-level messaging details of TLS, and the higher level handshake logic. Variants
like cTLS, DTLS 1.3, QUIC, only need to re-implement the MPS abstraction boundary, but keep the handshake logic intact,
while variants like KemTLS can keep the MPS implementation but build a different handshake layer on top.

MPS also aims to support future development around _Post Quantum Cryptography_: Specifically, it offers a _streaming
interface_ to the handshake layer, whereby handshake messages can be processed gradually as they arrive, without prior reassembly in
RAM. This allows some memory hungry Post-Quantum schemes to be implemented with small amounts of RAM.

MPS is controlled by the configuration option `MBEDTLS_SSL_USE_MPS`, which is enabled by default.

# Known limitations

Please consult the [issues](https://github.com/hannestschofenig/mbedtls/issues) for a complete list of issues. Here we
focus on the main limitations.

## Dual TLS 1.2 - TLS 1.3 build

You can currently not compile TLS 1.2 and TLS 1.3 alongside each other. In the default configuration, TLS 1.3 will be
enabled, but TLS 1.2 is disabled. We're working on resolving this.
