#include <stddef.h>
#include <stdint.h>

#include "common.h"
#include "cpu.h"

static volatile uint16_t optblocker_u16;

static inline int
aegis_verify_n(const uint8_t *x_, const uint8_t *y_, const int n)
{
    const volatile uint8_t *volatile x = (const volatile uint8_t *volatile) x_;
    const volatile uint8_t *volatile y = (const volatile uint8_t *volatile) y_;
    volatile uint16_t d                = 0U;
    int               i;

    for (i = 0; i < n; i++) {
        d |= x[i] ^ y[i];
    }
#if defined(__GNUC__) || defined(__clang__)
    __asm__("" : "+r"(d) :);
#endif
    d--;
    d = ((d >> 13) ^ optblocker_u16) >> 2;

    return (int) d - 1;
}

int
aegis_verify_16(const uint8_t *x, const uint8_t *y)
{
    return aegis_verify_n(x, y, 16);
}

int
aegis_verify_32(const uint8_t *x, const uint8_t *y)
{
    return aegis_verify_n(x, y, 32);
}

extern int aegis128l_pick_best_implementation(void);
extern int aegis128x2_pick_best_implementation(void);
extern int aegis128x4_pick_best_implementation(void);
extern int aegis256_pick_best_implementation(void);
extern int aegis256x2_pick_best_implementation(void);
extern int aegis256x4_pick_best_implementation(void);

int
aegis_init(void)
{
    static int initialized = 0;

    if (initialized) {
        return 0;
    }
    if (aegis_runtime_get_cpu_features() != 0) {
        return 0;
    }
    if (aegis128l_pick_best_implementation() != 0 || aegis128x2_pick_best_implementation() != 0 ||
        aegis128x4_pick_best_implementation() != 0 || aegis256_pick_best_implementation() != 0 ||
        aegis256x2_pick_best_implementation() != 0 || aegis256x4_pick_best_implementation() != 0) {
        return -1;
    }
    initialized = 1;

    return 0;
}

#if defined(_MSC_VER)
#    pragma section(".CRT$XCU", read)
static void __cdecl _do_aegis_init(void);
__declspec(allocate(".CRT$XCU")) void (*aegis_init_constructor)(void) = _do_aegis_init;
#else
static void _do_aegis_init(void) __attribute__((constructor));
#endif

static void
_do_aegis_init(void)
{
    (void) aegis_init();
}
