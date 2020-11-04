#include <stdio.h>
#include "keyed_func.h"
extern uint8_t half_round_decrypt(uint8_t state[AES_BLOCK_SIZE], int index, uint8_t key_byte);

void print_vect(uint8_t *v, int n)
{
    int i;
    for (i = 0; i < n; i++)
    {
        printf("%x, ", v[i]);
    }
    printf("\n");
}

int main(int argc, char *argv[])
{
    uint8_t k[16];
    uint8_t l[16];
    uint8_t p[16];
    const uint8_t k1[16] = {0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2,
                            0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c};

    const uint8_t k2[16] = {0x4e, 0x61, 0x9a, 0xea, 0x1f, 0xa5, 0x5c,
                            0x5e, 0xda, 0xc0, 0x28, 0x53, 0xdb, 0x84, 0xb0, 0xd0};

    uint8_t t[256][16];
    int i = 0;
    int sum = 0;
    int j = 0;
    for (i = 0; i < 256; i++)
    {
        t[i][0] = (uint8_t)i;
        for (j = 1; j < 16; j++)
        {
            t[i][j] = 0;
        }
    }

    for (i = 0; i < 256; i++)
    {
        aes128_enc(t[i], k1, 4, 0);
    }

    // printf("%d th :", 0);
    // print_vect(t[1], 16);

    // aes128_enc(t[1], k1, 2, 0);

    // printf("%d th :", 0);
    // print_vect(t[1], 16);

    next_aes128_round_key(k1, k, 0);
    next_aes128_round_key(k, l, 1);
    next_aes128_round_key(l, p, 2);
    next_aes128_round_key(p, k, 3);

    // aes128_enc(t[1], k, 1, 0);

    // printf("%d th :", 0);
    // print_vect(t[1], 16);

    // next_aes128_round_key(l, p, 2);
    // uint8_t a = half_round_decrypt(t[1], 1, l[13]);
    // printf("a = %x\n", a);

    for (i = 0; i < 256; i++)
    {
        t[i][0] = half_round_decrypt(t[i], 0, k[0]);
    }

    for (i = 0; i < 256; i++)
    {
        sum ^= t[i][0];
    }

    printf("sum = %d", sum);

    return 0;
}
