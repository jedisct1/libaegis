# libaegis

Portable C implementations of the [AEGIS](https://datatracker.ietf.org/doc/draft-irtf-cfrg-aegis-aead/) family of authenticated ciphers (AEGIS-128L, AEGIS-128X2, AEGIS-128X4, AEGIS-256, AEGIS-256X2, AEGIS-256X4), with runtime CPU detection.

## Features

- AEGIS-128L with 16 and 32 bytes tags (software, AES-NI, ARM Crypto)
- AEGIS-128X2 with 16 and 32 bytes tags (software, VAES + AVX2, AES-NI, ARM Crypto)
- AEGIS-128X4 with 16 and 32 bytes tags (software, AVX512, VAES + AVX2, AES-NI, ARM Crypto)
- AEGIS-256 with 16 and 32 bytes tags (software, AES-NI, ARM Crypto)
- AEGIS-256X2 with 16 and 32 bytes tags (software, VAES + AVX2, AES-NI, ARM Crypto)
- AEGIS-256X4 with 16 and 32 bytes tags (software, AVX512, VAES + AVX2, AES-NI, ARM Crypto)
- Encryption and decryption with attached and detached tags
- Incremental encryption and decryption.
- Unauthenticated encryption and decryption (not recommended - only implemented for specific protocols)
- Deterministic pseudorandom stream generation.

## Installation

Note that the compiler makes a difference. Zig (or a recent `clang` with target-specific options such as `-march=native`) produces more efficient code than `gcc`.

### Compilation with `zig`:

```sh
zig build -Drelease
```

The library and headers are installed in the `zig-out` folder.

To favor performance over side-channel mitigations on WebAssembly and on devices without hardware acceleration, add `-Dfavor-performance`:

```sh
zig build -Drelease -Dfavor-performance
```

A benchmark can also be built with the `-Dwith-benchmark` option:

```sh
zig build -Drelease -Dwith-benchmark
```

### Compilation with `cmake`:

```sh
mkdir build
cd build
cmake -DCMAKE_INSTALL_PREFIX=/install/prefix ..
make install
```

To favor performance over side-channel mitigations on WebAssembly and on devices without hardware acceleration, add `-DFAVOR_PERFORMANCE`.

### Direct inclusion

Copy everything in `src` directly into your project, and compile everything like regular C code. No special configuration is required.

## Usage

Include `<aegis.h>` and call `aegis_init()` prior to doing anything else with the library.

`aegis_init()` checks the CPU capabilities in order to later use the fastest implementations.

## Bindings

* [`aegis`](https://crates.io/crates/aegis) is a set of bindings for Rust.

## Libaegis users

* [`picotls`](https://github.com/h2o/picotls) is a TLS 1.3 implementation in C, with support for the AEGIS cipher suites.
* [`h2o`](https://h2o.examp1e.net) is an HTTP/{1,2,3} serverwith support for the AEGIS cipher suites.

## Benchmarks

Benchmarks of the `aegis` crate against other options for Rust:

### AMD Zen4

| cipher                       |     speed |
| ---------------------------- | --------: |
| aes128-gcm (`aes-gcm` crate) |  1.73 G/s |
| aes256-gcm (`aes-gcm` crate) |  1.86 G/s |
| chacha20-poly1305            |  2.47 G/s |
| aes256-gcm (`boring` crate)  |  5.14 G/s |
| aes128-gcm (`boring` crate)  |  5.92 G/s |
| aegis256                     | 14.36 G/s |
| aegis256x2                   | 26.92 G/s |
| aegis256x4                   | 42.82 G/s |
| aegis128l                    | 23.35 G/s |
| aegis128x2                   | 42.68 G/s |
| aegis128x4                   | 55.28 G/s |

### Macbook Pro - Apple M1

| cipher                       |      speed |
| ---------------------------- | ---------: |
| aes256-gcm (`aes-gcm` crate) | 139.66 M/s |
| aes128-gcm (`aes-gcm` crate) | 173.09 M/s |
| chacha20-poly1305            | 265.48 M/s |
| aes256-gcm (`boring` crate)  |   5.14 G/s |
| aes128-gcm (`boring` crate)  |   6.08 G/s |
| aegis256                     |   7.94 G/s |
| aegis256x2                   |  10.56 G/s |
| aegis256x4                   |  11.20 G/s |
| aegis128l                    |  14.27 G/s |
| aegis128x2                   |  15.98 G/s |
| aegis128x4                   |  12.01 G/s |