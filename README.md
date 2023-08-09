# libaegis

Portable C implementations of AEGIS (AEGIS-128L, AEGIS-128X2 and AEGIS-256), with runtime CPU detection.

## Features

- AEGIS-128L with 16 and 32 bytes tags (software, AES-NI, ARM Crypto)
- AEGIS-128X2 with 16 and 32 bytes tags (software, VAES + AVX2, AES-NI, ARM Crypto)
- AEGIS-256 with 16 and 32 bytes tags (software, AES-NI, ARM Crypto)
- Encryption and decryption with attached and detached tags
- Incremental encryption and decryption.

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

To avoid caching outputs, add `-Dnon-temporal-stores`:

```sh
zig build -Drelease -Dnon-temporal-stores
```

### Compilation with `cmake`:

```sh
mkdir build
cd build
cmake -DCMAKE_INSTALL_PREFIX=/install/prefix ..
make install
```

To favor performance over side-channel mitigations on WebAssembly and on devices without hardware acceleration, add `-DFAVOR_PERFORMANCE`.
To avoid caching outputs, add `-DNON_TEMPORAL_STORES`.

### Direct inclusion

Copy everything in `src` directly into your project, and compile everything like regular C code. No special configuration is required.

## Usage

Include `<aegis.h>` and call `aegis_init()` prior to doing anything else with the library.

`aegis_init()` checks the CPU capabilities in order to later use the fastest implementations. 

