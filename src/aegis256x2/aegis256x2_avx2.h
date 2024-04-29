#ifndef aegis256x2_avx2_H
#define aegis256x2_avx2_H

#include "../common/common.h"
#include "implementations.h"

#ifdef HAVE_VAESINTRIN_H
extern struct aegis256x2_implementation aegis256x2_avx2_implementation;
#endif

#endif