#include "attack.h"
/**
 * performs substraction x - y mod 16
*/
int modular_substraction_16(int x, int y)
{
    return ((x - y) % 16) + ((x >= y) ? 0 : 16);
}
extern void print_vect(uint8_t *v, int n);
void shuffle(uint8_t *array, size_t n)
{
    if (n > 1)
    {
        size_t i;
        for (i = 0; i < n - 1; i++)
        {
            size_t j = i + rand() / (RAND_MAX / (n - i) + 1);
            FILE *fp = fopen("/dev/urandom", "r");
            int seed = 0;
            fread(&seed, sizeof seed, 1, fp);
            fclose(fp);
            srand(seed);
            uint8_t t = array[j];
            array[j] = array[i];
            array[i] = t;
        }
    }
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

/**
 * Gets a random key of 16 bytes from the file /dev/urandom 
 * if an error occurs it terminates the proccess
*/
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
 * Performs the 3 and 1/2 AES encryption on @set with a random key  
 * and puts this key in @key 
*/
void query_3_and_half(uint8_t set[256][16], uint8_t key[AES_128_KEY_SIZE])
{
    int i = 0;
    fetch_random_key(key);
    for (i = 0; i < 256; i++)
    {
        aes128_enc(set[i], key, 4, 0);
    }

    return;
}

void generate_set(uint8_t set[256][AES_BLOCK_SIZE], uint8_t c)
{
    int i = 0, j = 0;
    for (i = 0; i < 256; i++)
    {
        set[i][0] = i;
        for (j = 1; j < AES_BLOCK_SIZE; j++)
        {
            set[i][j] = c;
        }
    }

    return;
}

void compute_possible_key(uint8_t enc_set[256][AES_BLOCK_SIZE], uint8_t result_key[AES_128_KEY_SIZE])
{
    int i = 0, j = 0, k = 0;
    uint8_t prev_key[AES_128_KEY_SIZE];
    for (i = 0; i < AES_128_KEY_SIZE; i++)
    {
        for (j = 0; j < 256; j++)
        {
            int sum = 0;
            for (k = 0; k < 256; k++)
            {
                sum ^= half_round_decrypt(enc_set[k], i, j);
            }
            if (sum == 0)
            {
                if (i % 4 == 0)
                {
                    result_key[i] = j;
                }
                else
                {
                    result_key[modular_substraction_16(i, 4)] = j;
                }
                break;
            }
        }
    }
}

uint8_t max_repeating_byte(uint8_t vectors[TRIAL_NUM][AES_128_KEY_SIZE], int index)
{
    uint8_t maxElement;
    int i, j, maxCount, count;
    maxCount = -1;
    for (i = 0; i < TRIAL_NUM; i++)
    {
        count = 1;
        for (j = i + 1; j < TRIAL_NUM; j++)
        {
            if (vectors[j][index] == vectors[i][index])
            {
                count++;
                if (count > maxCount)
                {
                    maxCount = count;
                    maxElement = vectors[j][index];
                }
            }
        }
    }
    return maxElement;
}

void attack(uint8_t original_key[AES_128_KEY_SIZE], uint8_t found_key[AES_128_KEY_SIZE])
{
    int i = 0, j = 0;
    uint8_t set[256][AES_BLOCK_SIZE];
    uint8_t possible_keys[TRIAL_NUM][AES_128_KEY_SIZE];
    uint8_t ekey[AES_128_KEY_SIZE * 2];
    int nk, pk;
    for (i = 0; i < TRIAL_NUM; i++)
    {
        generate_set(set, (i * 52) % 256);
        for (j = 0; j < 256; j++)
        {
            aes128_enc(set[j], original_key, 4, 0);
        }
        compute_possible_key(set, possible_keys[i]);
    }
    puts("");
    nk = 0;
    pk = 16;
    for (i = 0; i < AES_128_KEY_SIZE; i++)
    {
        ekey[i + nk] = max_repeating_byte(possible_keys, i);
    }

    printf("4k : ");
    print_vect(ekey + nk, 16);

    nk = 16;
    pk = 0;

    for (i = 0; i < 4; i++)
    {
        pk = (pk + 16) & 0x10;
        nk = (nk + 16) & 0x10;
        prev_aes128_round_key(ekey + nk, ekey + pk, 3 - i);
    }

    printf("nk : ");
    print_vect(ekey + nk, 16);
    printf("pk : ");
    print_vect(ekey + pk, 16);
    printf("ok : ");
    print_vect(original_key, 16);
}
