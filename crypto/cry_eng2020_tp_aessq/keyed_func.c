#include "aes-128_enc.h"
#include <string.h>

#define NB_ROUNDS 3

void keyed_function(uint8_t x[AES_BLOCK_SIZE], uint8_t k1[AES_128_KEY_SIZE], 
                    uint8_t k2[AES_128_KEY_SIZE] )
{
    uint8_t block_enc_with_k1[AES_BLOCK_SIZE];
    uint8_t block_enc_with_k2[AES_BLOCK_SIZE];
    int i;
    
    memcpy(x, block_enc_with_k1, AES_BLOCK_SIZE);
    memcpy(x, block_enc_with_k2, AES_BLOCK_SIZE);

    aes128_enc(block_enc_with_k1, k1, NB_ROUNDS, 0);
    aes128_enc(block_enc_with_k2, k2, NB_ROUNDS, 0);

    for(i = 0; i < AES_BLOCK_SIZE ; i++)
        x[i] = block_enc_with_k1[i] ^ block_enc_with_k2[i];
}