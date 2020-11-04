#include "attack.h"
/**
 * performs substraction x - y mod 16
*/
int modular_substraction_16(int x, int y)
{
    return ((x - y) % 16) + ((x >= y) ? 0 : 16);
}

/**
 * @state is needed to look up the original byte ie the one before the shift
 * @index is the index of the byte to decrypt (expected to be in [0-15])
 * @key_byte is the byte of the key that was xored with the state byte
 * to decrypt, must be determined before call
 * ex: to decrypt the 2nd byte ie state[1] -> key_byte = key[13], for state[5] -> key[1] ...
*/
uint8_t half_round_decrypt(uint8_t state[AES_BLOCK_SIZE], int index, uint8_t key_byte)
{
    uint8_t dec = 0;

    if (index % 4 != 0)
    {
        // inverting the shift
        dec = state[modular_substraction_16(index, 4)];
    }
    else // index in first row
    {
        dec = state[index];
    }

    dec ^= key_byte;
    dec = Sinv[dec];
    return dec;
}

void fetch_random_key(uint8_t *key)
{
    FILE *fp = fopen("/dev/urandom", "r");
    if (fp == NULL)
    {
        fprintf(stderr, "Failed to open file /dev/urandom. Exiting now.\n");
        exit(1);
    }
    int bytes_read = fread(key, sizeof(uint8_t), AES_128_KEY_SIZE, fp);
    if (bytes_read < 0)
    {
        fprintf(stderr, "Failed to read 16 bytes from file /dev/urandom. Exiting now.\n");
        exit(1);
    }

    fclose(fp);
    return;
}

/**
 * returns the key used for the encryption
*/
uint8_t *query_3_and_half(uint8_t set[256][16])
{
    int i = 0;
    uint8_t key[AES_128_KEY_SIZE];
    fetch_random_key(key);
    for (i = 0; i < 256; i++)
    {
        aes128_enc(set[i], key, 4, 0);
    }

    return key;
}