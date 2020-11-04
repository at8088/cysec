#if !defined(KEYED_FUNC)
#define KEYED_FUNC

#include "aes-128_enc.h"

#define NB_ROUNDS 3

void keyed_function(uint8_t x[AES_BLOCK_SIZE], uint8_t k1[AES_128_KEY_SIZE],
                    uint8_t k2[AES_128_KEY_SIZE]);

#endif // KEYED_FUNC
