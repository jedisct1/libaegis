# libaegis

Portable C implementations of AEGIS (AEGIS-128L and AEGIS-256), with runtime CPU detection.

## Features

- AEGIS-128L with 16 and 32 bytes tags
- AEGIS-256 with 16 and 32 bytes tags
- Encryption and decryption with attached and detached tags
- Incremental encryption and decryption.

## Installation

### Compilation with `zig`:

```sh
zig build -Drelease
```

The library is installed in the `zig-out/lib` folder.

Public inludes are in the `src/include` folder.

### Compilation with `cmake`:

```sh
mkdir build
cd build
cmake -DCMAKE_INSTALL_PREFIX=/install/prefix ..
make install
```

### Direct inclusion

Copy everything in `src` directly into your project, and compile everything like regular C code. No special configuration is required.

