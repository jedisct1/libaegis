#ifndef aegis_H
#define aegis_H

#include <stdint.h>

#include "aegis128l.h"
#include "aegis256.h"

int aegis_init(void);

int aegis_verify_16(const uint8_t *x, const uint8_t *y);

int aegis_verify_32(const uint8_t *x, const uint8_t *y);

#endif