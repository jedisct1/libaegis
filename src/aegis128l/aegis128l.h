#ifndef aegis128l_H
#define aegis128l_H

#include <stddef.h>
#include <stdint.h>

#define aegis128l_KEYBYTES      16
#define aegis128l_NPUBBYTES     16
#define aegis128l_ABYTES_MIN    16
#define aegis128l_ABYTES_MAX    32
#define aegis128l_TAILBYTES_MAX 31

typedef struct aegis128l_state {
    uint8_t opaque[256];
} aegis128l_state;

size_t aegis128l_keybytes(void);

size_t aegis128l_npubbytes(void);

size_t aegis128l_abytes_min(void);

size_t aegis128l_abytes_max(void);

size_t aegis128l_tailbytes_max(void);

int aegis128l_encrypt_detached(uint8_t *c, uint8_t *mac, size_t maclen, const uint8_t *m,
                               size_t mlen, const uint8_t *ad, size_t adlen, const uint8_t *npub,
                               const uint8_t *k);

int aegis128l_decrypt_detached(uint8_t *m, const uint8_t *c, size_t clen, const uint8_t *mac,
                               size_t maclen, const uint8_t *ad, size_t adlen, const uint8_t *npub,
                               const uint8_t *k);

int aegis128l_encrypt(uint8_t *c, size_t maclen, const uint8_t *m, size_t mlen, const uint8_t *ad,
                      size_t adlen, const uint8_t *npub, const uint8_t *k);

int aegis128l_decrypt(uint8_t *m, const uint8_t *c, size_t clen, size_t maclen, const uint8_t *ad,
                      size_t adlen, const uint8_t *npub, const uint8_t *k);

void aegis128l_state_init(aegis128l_state *st_, const uint8_t *ad, size_t adlen,
                          const uint8_t *npub, const uint8_t *k);

int aegis128l_state_encrypt_update(aegis128l_state *st_, uint8_t *c, size_t clen_max,
                                   size_t *written, const uint8_t *m, size_t mlen);

int aegis128l_state_encrypt_detached_final(aegis128l_state *st_, uint8_t *c, size_t clen_max,
                                           size_t *written, uint8_t *mac, size_t maclen);

int aegis128l_state_encrypt_final(aegis128l_state *st_, uint8_t *c, size_t clen_max,
                                  size_t *written, size_t maclen);

int aegis_init(void);

#endif