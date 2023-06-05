#include <errno.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "aegis128l_aesni.h"
#include "aegis128l_armcrypto.h"
#include "aegis128l_soft.h"
#include "cpu.h"

static const aegis128l_implementation *implementation = &aegis128l_soft_implementation;

size_t
aegis128l_keybytes(void)
{
    return aegis128l_KEYBYTES;
}

size_t
aegis128l_npubbytes(void)
{
    return aegis128l_NPUBBYTES;
}

size_t
aegis128l_abytes_min(void)
{
    return aegis128l_ABYTES_MIN;
}

size_t
aegis128l_abytes_max(void)
{
    return aegis128l_ABYTES_MAX;
}

int
aegis128l_encrypt_detached(uint8_t *c, uint8_t *mac, size_t maclen, const uint8_t *m, size_t mlen,
                           const uint8_t *ad, size_t adlen, const uint8_t *npub, const uint8_t *k)
{
    if (maclen != 16 && maclen != 32) {
        return -1;
    }
    return implementation->encrypt_detached(c, mac, maclen, m, mlen, ad, adlen, npub, k);
}

int
aegis128l_decrypt_detached(uint8_t *m, const uint8_t *c, size_t clen, const uint8_t *mac,
                           size_t maclen, const uint8_t *ad, size_t adlen, const uint8_t *npub,
                           const uint8_t *k)
{
    if (maclen != 16 && maclen != 32) {
        return -1;
    }
    return implementation->decrypt_detached(m, c, clen, mac, maclen, ad, adlen, npub, k);
}

int
aegis128l_encrypt(uint8_t *c, size_t maclen, const uint8_t *m, size_t mlen, const uint8_t *ad,
                  size_t adlen, const uint8_t *npub, const uint8_t *k)
{
    return aegis128l_encrypt_detached(c, c + mlen, maclen, m, mlen, ad, adlen, npub, k);
}

int
aegis128l_decrypt(uint8_t *m, const uint8_t *c, size_t clen, size_t maclen, const uint8_t *ad,
                  size_t adlen, const uint8_t *npub, const uint8_t *k)
{
    int ret = -1;

    if (clen >= maclen) {
        ret = aegis128l_decrypt_detached(m, c, clen - maclen, c + clen - maclen, maclen, ad, adlen,
                                         npub, k);
    }
    return ret;
}

void
aegis128l_state_init(aegis128l_state *st_, const uint8_t *ad, size_t adlen, const uint8_t *npub,
                     const uint8_t *k)
{
    implementation->state_init(st_, ad, adlen, npub, k);
}

size_t
aegis128l_state_encrypt_update(aegis128l_state *st_, uint8_t *c, const uint8_t *m, size_t mlen)
{
    return implementation->state_encrypt_update(st_, c, m, mlen);
}

size_t
aegis128l_state_encrypt_detached_final(aegis128l_state *st_, uint8_t *c, uint8_t *mac,
                                       size_t maclen)
{
    if (maclen != 16 && maclen != 32) {
        return (size_t) -1;
    }
    return implementation->state_encrypt_detached_final(st_, c, mac, maclen);
}

size_t
aegis128l_state_encrypt_final(aegis128l_state *st_, uint8_t *c, uint8_t *mac, size_t maclen)
{
    if (maclen != 16 && maclen != 32) {
        return (size_t) -1;
    }
    return implementation->state_encrypt_final(st_, c, maclen);
}

static int
aegis128l_pick_best_implementation(void)
{
    implementation = &aegis128l_soft_implementation;

#ifdef __aarch64__
    if (aegis_runtime_has_armcrypto()) {
        implementation = &aegis128l_armcrypto_implementation;
        return 0;
    }
#endif

#if defined(__x86_64__) || defined(__i386__)
    if (aegis_runtime_has_aesni() && aegis_runtime_has_avx()) {
        implementation = &aegis128l_aesni_implementation;
        return 0;
    }
#endif

    return 0; /* LCOV_EXCL_LINE */
}

int
aegis_init(void)
{
    if (aegis_runtime_get_cpu_features() != 0) {
        return -1;
    }
    aegis128l_pick_best_implementation();

    return 0;
}