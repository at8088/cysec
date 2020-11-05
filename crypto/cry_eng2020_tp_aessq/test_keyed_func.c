#include <stdio.h>
#include <stdint.h>
#include "aes-128_enc.h"
extern void keyed_function(uint8_t x[AES_BLOCK_SIZE], uint8_t k1[AES_128_KEY_SIZE],
                           uint8_t k2[AES_128_KEY_SIZE]);
extern void generate_set(uint8_t set[256][AES_BLOCK_SIZE], uint8_t c);

int main(int argc, char const *argv[])
{
    uint8_t set[256][AES_BLOCK_SIZE];
    uint8_t key1[AES_128_KEY_SIZE] = {0x75, 0xc6, 0xa6, 0xe8, 0x26, 0x15,
                                      0x83, 0x4e, 0x6b, 0xd0, 0xc1, 0x71, 0x81, 0xe2, 0xcf, 0x0a};

    uint8_t key2[AES_128_KEY_SIZE] = {0x52, 0xe9, 0x0c, 0x72, 0xd6, 0xb2,
                                      0x49, 0x14, 0x4a, 0xdd, 0x40, 0x12, 0xc1, 0x88, 0x48, 0x95};

    int i = 0, sum = 0;
    printf("Test of the distinguisher on the keyed function.\n");
    generate_set(set, 69); // "random" set
    printf("Delta set generated.\n");
    for (i = 0; i < 256; i++)
    {
        keyed_function(set[i], key1, key2);
    }
    printf("Keyed function applied on all blocks of the set.\n");
    for (i = 0; i < 256; i++)
    {
        sum ^= set[i][0];
    }

    printf("The sum of all the bytes of index 0 in the Delta set = %d\n", sum);
    if (sum == 0)
    {
        printf("The distinguisher works with the keyed function as well.\n");
    }

    return 0;
}
