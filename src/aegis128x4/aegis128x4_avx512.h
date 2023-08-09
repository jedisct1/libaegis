#ifndef aegis128x4_avx512_H
#define aegis128x4_avx512_H

#include "../common/common.h"
#include "implementations.h"

#ifdef HAVE_VAESINTRIN_H
extern struct aegis128x4_implementation aegis128x4_avx512_implementation;
#endif

#endif