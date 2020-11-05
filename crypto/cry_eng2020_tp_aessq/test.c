#include "attack.h"
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
    uint8_t d[256][16];
    int i = 0, j = 0;
    // next_aes128_round_key(k1, k, 0);
    // next_aes128_round_key(k, l, 1);
    // prev_aes128_round_key(l, p, 1);
    // prev_aes128_round_key(p, k, 0);
    // print_vect(k, 16);
    attack(k1, l);
    return 0;
}
