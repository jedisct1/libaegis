#ifndef aegis256x4_avx512_H
#define aegis256x4_avx512_H

#include "../common/common.h"
#include "implementations.h"

#ifdef HAVE_VAESINTRIN_H
extern struct aegis256x4_implementation aegis256x4_avx512_implementation;
#endif

#endif