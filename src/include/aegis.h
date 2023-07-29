#ifndef aegis_H
#define aegis_H

#include <stdint.h>

#include "aegis128l.h"
#include "aegis256.h"

/* Initialize the AEGIS library.
 *
 * This function does runtime CPU capability detection, and must be called once
 * in your application before doing anything else with the library.
 *
 * If you don't, AEGIS will still work, but it may be much slower.
 */
int aegis_init(void);

/* Compare two 16-byte blocks for equality.
 *
 * This function is designed to be used in constant-time code.
 *
 * Returns 0 if the blocks are equal, -1 otherwise.
 */
int aegis_verify_16(const uint8_t *x, const uint8_t *y);

/* Compare two 32-byte blocks for equality.
 *
 * This function is designed to be used in constant-time code.
 *
 * Returns 0 if the blocks are equal, -1 otherwise.
 */
int aegis_verify_32(const uint8_t *x, const uint8_t *y);

#endif