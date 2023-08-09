#ifndef aegis128x2_H
#define aegis128x2_H

#include <stddef.h>
#include <stdint.h>

/* The length of an AEGIS key, in bytes */
#define aegis128x2_KEYBYTES 16

/* The length of an AEGIS nonce, in bytes */
#define aegis128x2_NPUBBYTES 16

/* The minimum length of an AEGIS authentication tag, in bytes */
#define aegis128x2_ABYTES_MIN 16

/* The maximum length of an AEGIS authentication tag, in bytes */
#define aegis128x2_ABYTES_MAX 32

/*
 * When using AEGIS in incremental mode, this is the maximum number
 * of leftover ciphertext bytes that can be returned at finalization.
 */
#define aegis128x2_TAILBYTES_MAX 63

/* An AEGIS state, for incremental updates */
typedef struct aegis128x2_state {
    uint8_t opaque[448];
} aegis128x2_state;

/* The length of an AEGIS key, in bytes */
size_t aegis128x2_keybytes(void);

/* The length of an AEGIS nonce, in bytes */
size_t aegis128x2_npubbytes(void);

/* The minimum length of an AEGIS authentication tag, in bytes */
size_t aegis128x2_abytes_min(void);

/* The maximum length of an AEGIS authentication tag, in bytes */
size_t aegis128x2_abytes_max(void);

/*
 * When using AEGIS in incremental mode, this is the maximum number
 * of leftover ciphertext bytes that can be returned at finalization.
 */
size_t aegis128x2_tailbytes_max(void);

/*
 * Encrypt a message with AEGIS in one shot mode, returning the tag and the ciphertext separately.
 *
 * c: ciphertext output buffer
 * mac: authentication tag output buffer
 * maclen: length of the authentication tag to generate (16 or 32)
 * m: plaintext input buffer
 * mlen: length of the plaintext
 * ad: additional data input buffer
 * adlen: length of the additional data
 * npub: nonce input buffer (16 bytes)
 * k: key input buffer (16 bytes)
 */
int aegis128x2_encrypt_detached(uint8_t *c, uint8_t *mac, size_t maclen, const uint8_t *m,
                                size_t mlen, const uint8_t *ad, size_t adlen, const uint8_t *npub,
                                const uint8_t *k);

/*
 * Decrypt a message with AEGIS in one shot mode, returning the tag and the ciphertext separately.
 *
 * m: plaintext output buffer
 * c: ciphertext input buffer
 * clen: length of the ciphertext
 * mac: authentication tag input buffer
 * maclen: length of the authentication tag (16 or 32)
 * ad: additional data input buffer
 * adlen: length of the additional data
 * npub: nonce input buffer (16 bytes)
 * k: key input buffer (16 bytes)
 *
 * Returns 0 if the ciphertext is authentic, -1 otherwise.
 */
int aegis128x2_decrypt_detached(uint8_t *m, const uint8_t *c, size_t clen, const uint8_t *mac,
                                size_t maclen, const uint8_t *ad, size_t adlen, const uint8_t *npub,
                                const uint8_t *k) __attribute__((warn_unused_result));

/*
 * Encrypt a message with AEGIS in one shot mode, returning the tag and the ciphertext together.
 *
 * c: ciphertext output buffer
 * maclen: length of the authentication tag to generate (16 or 32)
 * m: plaintext input buffer
 * mlen: length of the plaintext
 * ad: additional data input buffer
 * adlen: length of the additional data
 * npub: nonce input buffer (16 bytes)
 * k: key input buffer (16 bytes)
 */
int aegis128x2_encrypt(uint8_t *c, size_t maclen, const uint8_t *m, size_t mlen, const uint8_t *ad,
                       size_t adlen, const uint8_t *npub, const uint8_t *k);

/*
 * Decrypt a message with AEGIS in one shot mode, returning the tag and the ciphertext together.
 *
 * m: plaintext output buffer
 * c: ciphertext input buffer
 * clen: length of the ciphertext
 * maclen: length of the authentication tag (16 or 32)
 * ad: additional data input buffer
 * adlen: length of the additional data
 * npub: nonce input buffer (16 bytes)
 * k: key input buffer (16 bytes)
 *
 * Returns 0 if the ciphertext is authentic, -1 otherwise.
 */
int aegis128x2_decrypt(uint8_t *m, const uint8_t *c, size_t clen, size_t maclen, const uint8_t *ad,
                       size_t adlen, const uint8_t *npub, const uint8_t *k)
    __attribute__((warn_unused_result));

/*
 * Initialize a state for incremental encryption or decryption.
 *
 * st_: state to initialize
 * ad: additional data input buffer
 * adlen: length of the additional data
 * npub: nonce input buffer (16 bytes)
 * k: key input buffer (16 bytes)
 */
void aegis128x2_state_init(aegis128x2_state *st_, const uint8_t *ad, size_t adlen,
                           const uint8_t *npub, const uint8_t *k);

/*
 * Encrypt a message chunk.
 * The same function can be used regardless of whether the tag will be attached or not.
 *
 * st_: state to update
 * c: ciphertext output buffer
 * clen_max: length of the ciphertext chunk buffer (must be >= mlen)
 * written: number of ciphertext bytes actually written
 * m: plaintext input buffer
 * mlen: length of the plaintext
 *
 * Return 0 on success, -1 on failure.
 */
int aegis128x2_state_encrypt_update(aegis128x2_state *st_, uint8_t *c, size_t clen_max,
                                    size_t *written, const uint8_t *m, size_t mlen);

/*
 * Finalize the incremental encryption and generate the authentication tag.
 *
 * st_: state to finalize
 * c: output buffer for the final ciphertext chunk
 * clen_max: length of the ciphertext chunk buffer (must be >= remaining bytes)
 * written: number of ciphertext bytes actually written
 * mac: authentication tag output buffer
 * maclen: length of the authentication tag to generate (16 or 32)
 *
 * Return 0 on success, -1 on failure.
 */
int aegis128x2_state_encrypt_detached_final(aegis128x2_state *st_, uint8_t *c, size_t clen_max,
                                            size_t *written, uint8_t *mac, size_t maclen);

/*
 * Finalize the incremental encryption and attach the authentication tag
 * to the final ciphertext chunk.
 *
 * st_: state to finalize
 * c: output buffer for the final ciphertext chunk
 * clen_max: length of the ciphertext chunk buffer (must be >= remaining bytes+maclen)
 * written: number of ciphertext bytes actually written
 * maclen: length of the authentication tag to generate (16 or 32)
 *
 * Return 0 on success, -1 on failure.
 */
int aegis128x2_state_encrypt_final(aegis128x2_state *st_, uint8_t *c, size_t clen_max,
                                   size_t *written, size_t maclen);

/*
 * Decrypt a message chunk.
 *
 * The output should never be released to the caller until the tag has been verified.
 *
 * st_: state to update
 * m: plaintext output buffer
 * mlen_max: length of the plaintext chunk buffer (must be >= clen)
 * written: number of plaintext bytes actually written
 * c: ciphertext chunk input buffer
 * clen: length of the ciphertext chunk
 *
 * Return 0 on success, -1 on failure.
 */
int aegis128x2_state_decrypt_detached_update(aegis128x2_state *st_, uint8_t *m, size_t mlen_max,
                                             size_t *written, const uint8_t *c, size_t clen)
    __attribute__((warn_unused_result));

/*
 * Decrypt the final message chunk and verify the authentication tag.
 *
 * st_: state to finalize
 * m: plaintext output buffer
 * mlen_max: length of the plaintext chunk buffer (must be >= remaining bytes)
 * written: number of plaintext bytes actually written
 * mac: authentication tag input buffer
 * maclen: length of the authentication tag (16 or 32)
 *
 * Return 0 on success, -1 on failure.
 */
int aegis128x2_state_decrypt_detached_final(aegis128x2_state *st_, uint8_t *m, size_t mlen_max,
                                            size_t *written, const uint8_t *mac, size_t maclen)
    __attribute__((warn_unused_result));

#endif