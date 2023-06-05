#ifndef common_H
#define common_H

#include <stddef.h>
#include <stdint.h>

#include "aegis128l.h"

#ifdef __linux__
#define HAVE_SYS_AUXV_H
#define HAVE_GETAUXVAL
#endif
#ifdef __ANDROID_API__
#define HAVE_ANDROID_GETCPUFEATURES
#endif
#if defined(__i386__) || defined(__x86_64__)
#define HAVE_CPUID
#define NATIVE_LITTLE_ENDIAN
#endif
#ifdef __x86_64__
#define HAVE_AVXINTRIN_H
#define HAVE_AVX2INTRIN_H
#define HAVE_AVX512FINTRIN_H
#define HAVE_WMMINTRIN_H
#endif
#ifdef __aarch64__

#endif

#if defined(__INTEL_COMPILER) || defined(_MSC_VER)
#define CRYPTO_ALIGN(x) __declspec(align(x))
#else
#define CRYPTO_ALIGN(x) __attribute__((aligned(x)))
#endif

#define LOAD32_LE(SRC) load32_le(SRC)
static inline uint32_t
load32_le(const uint8_t src[4])
{
#ifdef NATIVE_LITTLE_ENDIAN
    uint32_t w;
    memcpy(&w, src, sizeof w);
    return w;
#else
    uint32_t w = (uint32_t) src[0];
    w |= (uint32_t) src[1] << 8;
    w |= (uint32_t) src[2] << 16;
    w |= (uint32_t) src[3] << 24;
    return w;
#endif
}

#define STORE32_LE(DST, W) store32_le((DST), (W))
static inline void
store32_le(uint8_t dst[4], uint32_t w)
{
#ifdef NATIVE_LITTLE_ENDIAN
    memcpy(dst, &w, sizeof w);
#else
    dst[0] = (uint8_t) w;
    w >>= 8;
    dst[1] = (uint8_t) w;
    w >>= 8;
    dst[2] = (uint8_t) w;
    w >>= 8;
    dst[3] = (uint8_t) w;
#endif
}

#define ROTL32(X, B) rotl32((X), (B))
static inline uint32_t
rotl32(const uint32_t x, const int b)
{
    return (x << b) | (x >> (32 - b));
}

#define COMPILER_ASSERT(X) (void) sizeof(char[(X) ? 1 : -1])

int aegis_verify_16(const uint8_t *x, const uint8_t *y);
int aegis_verify_32(const uint8_t *x, const uint8_t *y);

typedef struct aegis128l_implementation {
    int (*encrypt_detached)(uint8_t *c, uint8_t *mac, size_t maclen, const uint8_t *m, size_t mlen,
                            const uint8_t *ad, size_t adlen, const uint8_t *npub, const uint8_t *k);
    int (*decrypt_detached)(uint8_t *m, const uint8_t *c, size_t clen, const uint8_t *mac,
                            size_t maclen, const uint8_t *ad, size_t adlen, const uint8_t *npub,
                            const uint8_t *k);
    void (*state_init)(aegis128l_state *st_, const uint8_t *ad, size_t adlen, const uint8_t *npub,
                       const uint8_t *k);
    size_t (*state_encrypt_update)(aegis128l_state *st_, uint8_t *c, const uint8_t *m, size_t mlen);
    size_t (*state_encrypt_detached_final)(aegis128l_state *st_, uint8_t *c, uint8_t *mac,
                                           size_t maclen);
    size_t (*state_encrypt_final)(aegis128l_state *st_, uint8_t *c, size_t maclen);
} aegis128l_implementation;

#define aegis128l_KEYBYTES   16
#define aegis128l_NPUBBYTES  16
#define aegis128l_ABYTES_MIN 16
#define aegis128l_ABYTES_MAX 32

#endif