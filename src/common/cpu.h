#ifndef cpu_H
#define cpu_H

int aegis_runtime_get_cpu_features(void);

int aegis_runtime_has_neon(void);

int aegis_runtime_has_armcrypto(void);

int aegis_runtime_has_avx(void);

int aegis_runtime_has_avx2(void);

int aegis_runtime_has_avx512f(void);

int aegis_runtime_has_aesni(void);

int aegis_runtime_has_vaes(void);

#endif