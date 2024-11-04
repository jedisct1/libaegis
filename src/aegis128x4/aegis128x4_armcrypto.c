#if defined(__aarch64__) || defined(_M_ARM64)

#    include <errno.h>
#    include <stddef.h>
#    include <stdint.h>
#    include <stdlib.h>
#    include <string.h>

#    include "../common/common.h"
#    include "aegis128x4.h"
#    include "aegis128x4_armcrypto.h"

#    ifndef __ARM_FEATURE_CRYPTO
#        define __ARM_FEATURE_CRYPTO 1
#    endif
#    ifndef __ARM_FEATURE_AES
#        define __ARM_FEATURE_AES 1
#    endif

#    include <arm_neon.h>

#    ifdef __clang__
#        pragma clang attribute push(__attribute__((target("neon,crypto,aes"))), \
                                     apply_to = function)
#    elif defined(__GNUC__)
#        pragma GCC target("+simd+crypto")
#    endif

#    define AES_BLOCK_LENGTH  64
#    define AES_BLOCK1_LENGTH 16
#    define CHUNK_SIZE        512

typedef struct {
    uint8x16_t b0;
    uint8x16_t b1;
    uint8x16_t b2;
    uint8x16_t b3;
} aes_block_t;

/* -- */

typedef uint8x16_t aes_block1_t;

#    define AES_BLOCK1_XOR(A, B)       veorq_u8((A), (B))
#    define AES_BLOCK1_AND(A, B)       vandq_u8((A), (B))
#    define AES_BLOCK1_LOAD(A)         vld1q_u8(A)
#    define AES_BLOCK1_LOAD_64x2(A, B) vreinterpretq_u8_u64(vsetq_lane_u64((A), vmovq_n_u64(B), 1))
#    define AES_BLOCK1_STORE(A, B)     vst1q_u8((A), (B))
#    define AES_ENC1(A, B)             veorq_u8(vaesmcq_u8(vaeseq_u8((A), vmovq_n_u8(0))), (B))

static inline void
aegis128x4_update_b0(aes_block_t *const state, const aes_block1_t d1, const aes_block1_t d2)
{
    aes_block1_t tmp;

    tmp         = state[7].b0;
    state[7].b0 = AES_ENC1(state[6].b0, state[7].b0);
    state[6].b0 = AES_ENC1(state[5].b0, state[6].b0);
    state[5].b0 = AES_ENC1(state[4].b0, state[5].b0);
    state[4].b0 = AES_BLOCK1_XOR(AES_ENC1(state[3].b0, state[4].b0), d2);
    state[3].b0 = AES_ENC1(state[2].b0, state[3].b0);
    state[2].b0 = AES_ENC1(state[1].b0, state[2].b0);
    state[1].b0 = AES_ENC1(state[0].b0, state[1].b0);
    state[0].b0 = AES_BLOCK1_XOR(AES_ENC1(tmp, state[0].b0), d1);
}

static inline void
aegis128x4_update_b1(aes_block_t *const state, const aes_block1_t d1, const aes_block1_t d2)
{
    aes_block1_t tmp;

    tmp         = state[7].b1;
    state[7].b1 = AES_ENC1(state[6].b1, state[7].b1);
    state[6].b1 = AES_ENC1(state[5].b1, state[6].b1);
    state[5].b1 = AES_ENC1(state[4].b1, state[5].b1);
    state[4].b1 = AES_BLOCK1_XOR(AES_ENC1(state[3].b1, state[4].b1), d2);
    state[3].b1 = AES_ENC1(state[2].b1, state[3].b1);
    state[2].b1 = AES_ENC1(state[1].b1, state[2].b1);
    state[1].b1 = AES_ENC1(state[0].b1, state[1].b1);
    state[0].b1 = AES_BLOCK1_XOR(AES_ENC1(tmp, state[0].b1), d1);
}

static inline void
aegis128x4_update_b2(aes_block_t *const state, const aes_block1_t d1, const aes_block1_t d2)
{
    aes_block1_t tmp;

    tmp         = state[7].b2;
    state[7].b2 = AES_ENC1(state[6].b2, state[7].b2);
    state[6].b2 = AES_ENC1(state[5].b2, state[6].b2);
    state[5].b2 = AES_ENC1(state[4].b2, state[5].b2);
    state[4].b2 = AES_BLOCK1_XOR(AES_ENC1(state[3].b2, state[4].b2), d2);
    state[3].b2 = AES_ENC1(state[2].b2, state[3].b2);
    state[2].b2 = AES_ENC1(state[1].b2, state[2].b2);
    state[1].b2 = AES_ENC1(state[0].b2, state[1].b2);
    state[0].b2 = AES_BLOCK1_XOR(AES_ENC1(tmp, state[0].b2), d1);
}

static inline void
aegis128x4_update_b3(aes_block_t *const state, const aes_block1_t d1, const aes_block1_t d2)
{
    aes_block1_t tmp;

    tmp         = state[7].b3;
    state[7].b3 = AES_ENC1(state[6].b3, state[7].b3);
    state[6].b3 = AES_ENC1(state[5].b3, state[6].b3);
    state[5].b3 = AES_ENC1(state[4].b3, state[5].b3);
    state[4].b3 = AES_BLOCK1_XOR(AES_ENC1(state[3].b3, state[4].b3), d2);
    state[3].b3 = AES_ENC1(state[2].b3, state[3].b3);
    state[2].b3 = AES_ENC1(state[1].b3, state[2].b3);
    state[1].b3 = AES_ENC1(state[0].b3, state[1].b3);
    state[0].b3 = AES_BLOCK1_XOR(AES_ENC1(tmp, state[0].b3), d1);
}

/* -- */

static inline aes_block_t
AES_BLOCK_XOR(const aes_block_t a, const aes_block_t b)
{
    return (aes_block_t) { veorq_u8(a.b0, b.b0), veorq_u8(a.b1, b.b1), veorq_u8(a.b2, b.b2),
                           veorq_u8(a.b3, b.b3) };
}

static inline aes_block_t
AES_BLOCK_AND(const aes_block_t a, const aes_block_t b)
{
    return (aes_block_t) { vandq_u8(a.b0, b.b0), vandq_u8(a.b1, b.b1), vandq_u8(a.b2, b.b2),
                           vandq_u8(a.b3, b.b3) };
}

static inline aes_block_t
AES_BLOCK_LOAD(const uint8_t *a)
{
    return (aes_block_t) { vld1q_u8(a), vld1q_u8(a + 16), vld1q_u8(a + 32), vld1q_u8(a + 48) };
}

static inline aes_block_t
AES_BLOCK_LOAD_64x2(uint64_t a, uint64_t b)
{
    const uint8x16_t t = vreinterpretq_u8_u64(vsetq_lane_u64((a), vmovq_n_u64(b), 1));
    return (aes_block_t) { t, t, t, t };
}
static inline void
AES_BLOCK_STORE(uint8_t *a, const aes_block_t b)
{
    vst1q_u8(a, b.b0);
    vst1q_u8(a + 16, b.b1);
    vst1q_u8(a + 32, b.b2);
    vst1q_u8(a + 48, b.b3);
}

static inline aes_block_t
AES_ENC(const aes_block_t a, const aes_block_t b)
{
    return (aes_block_t) { veorq_u8(vaesmcq_u8(vaeseq_u8((a.b0), vmovq_n_u8(0))), (b.b0)),
                           veorq_u8(vaesmcq_u8(vaeseq_u8((a.b1), vmovq_n_u8(0))), (b.b1)),
                           veorq_u8(vaesmcq_u8(vaeseq_u8((a.b2), vmovq_n_u8(0))), (b.b2)),
                           veorq_u8(vaesmcq_u8(vaeseq_u8((a.b3), vmovq_n_u8(0))), (b.b3)) };
}

static inline void
aegis128x4_update(aes_block_t *const state, const aes_block_t d1, const aes_block_t d2)
{
    aes_block_t tmp;

    tmp      = state[7];
    state[7] = AES_ENC(state[6], state[7]);
    state[6] = AES_ENC(state[5], state[6]);
    state[5] = AES_ENC(state[4], state[5]);
    state[4] = AES_BLOCK_XOR(AES_ENC(state[3], state[4]), d2);
    state[3] = AES_ENC(state[2], state[3]);
    state[2] = AES_ENC(state[1], state[2]);
    state[1] = AES_ENC(state[0], state[1]);
    state[0] = AES_BLOCK_XOR(AES_ENC(tmp, state[0]), d1);
}

#    include "aegis128x4_common.h"

struct aegis128x4_implementation aegis128x4_armcrypto_implementation = {
    .encrypt_detached              = encrypt_detached,
    .decrypt_detached              = decrypt_detached,
    .encrypt_unauthenticated       = encrypt_unauthenticated,
    .decrypt_unauthenticated       = decrypt_unauthenticated,
    .stream                        = stream,
    .state_init                    = state_init,
    .state_encrypt_update          = state_encrypt_update,
    .state_encrypt_detached_final  = state_encrypt_detached_final,
    .state_encrypt_final           = state_encrypt_final,
    .state_decrypt_detached_update = state_decrypt_detached_update,
    .state_decrypt_detached_final  = state_decrypt_detached_final,
    .state_mac_update              = state_mac_update,
    .state_mac_final               = state_mac_final,
    .state_clone                   = state_clone,
};

#    ifdef __clang__
#        pragma clang attribute pop
#    endif

#endif
