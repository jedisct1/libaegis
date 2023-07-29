#ifndef aegis256_H
#define aegis256_H

#include <stddef.h>
#include <stdint.h>

#define aegis256_KEYBYTES      16
#define aegis256_NPUBBYTES     16
#define aegis256_ABYTES_MIN    16
#define aegis256_ABYTES_MAX    32
#define aegis256_TAILBYTES_MAX 31

typedef struct aegis256_state {
    uint8_t opaque[256];
} aegis256_state;

size_t aegis256_keybytes(void);

size_t aegis256_npubbytes(void);

size_t aegis256_abytes_min(void);

size_t aegis256_abytes_max(void);

size_t aegis256_tailbytes_max(void);

int aegis256_encrypt_detached(uint8_t *c, uint8_t *mac, size_t maclen, const uint8_t *m,
                              size_t mlen, const uint8_t *ad, size_t adlen, const uint8_t *npub,
                              const uint8_t *k);

int aegis256_decrypt_detached(uint8_t *m, const uint8_t *c, size_t clen, const uint8_t *mac,
                              size_t maclen, const uint8_t *ad, size_t adlen, const uint8_t *npub,
                              const uint8_t *k) __attribute__((warn_unused_result));

int aegis256_encrypt(uint8_t *c, size_t maclen, const uint8_t *m, size_t mlen, const uint8_t *ad,
                     size_t adlen, const uint8_t *npub, const uint8_t *k);

int aegis256_decrypt(uint8_t *m, const uint8_t *c, size_t clen, size_t maclen, const uint8_t *ad,
                     size_t adlen, const uint8_t *npub, const uint8_t *k)
    __attribute__((warn_unused_result));

void aegis256_state_init(aegis256_state *st_, const uint8_t *ad, size_t adlen, const uint8_t *npub,
                         const uint8_t *k);

int aegis256_state_encrypt_update(aegis256_state *st_, uint8_t *c, size_t clen_max, size_t *written,
                                  const uint8_t *m, size_t mlen);

int aegis256_state_encrypt_detached_final(aegis256_state *st_, uint8_t *c, size_t clen_max,
                                          size_t *written, uint8_t *mac, size_t maclen);

int aegis256_state_encrypt_final(aegis256_state *st_, uint8_t *c, size_t clen_max, size_t *written,
                                 size_t maclen);

int aegis256_state_decrypt_detached_update(aegis256_state *st_, uint8_t *m, size_t mlen_max,
                                           size_t *written, const uint8_t *c, size_t clen)
    __attribute__((warn_unused_result));

int aegis256_state_decrypt_detached_final(aegis256_state *st_, uint8_t *m, size_t mlen_max,
                                          size_t *written, const uint8_t *mac, size_t maclen)
    __attribute__((warn_unused_result));

#endif