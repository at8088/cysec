#include "attack.h"

void print_vect(uint8_t *v, int n)
{
    int i;
    printf("0x%02x", v[0]);
    for (i = 1; i < n; i++)
    {
        printf(", 0x%02x", v[i]);
    }
    printf(".\n");
}

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
 * Generates a Delta-set where the "star" element is at index 0
*/
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

/**
 * Takes an encrypted Delta-set @ enc_set and computes a possible 4th round key and puts in @ result_key
 * which may be a false positive.
*/
void compute_possible_key(uint8_t enc_set[256][AES_BLOCK_SIZE], uint8_t result_key[AES_128_KEY_SIZE])
{
    int i = 0, j = 0, k = 0;
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
/**
 * Takes all the possible keys and returns the byte to be the most likely in the actual key
 * which the byte that occurs the most in all the possible keys
*/
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

/**
 * Performs the 3-round distinguisher attack on AES-128
*/
int attack()
{
    int i = 0, j = 0;
    uint8_t set[256][AES_BLOCK_SIZE];
    uint8_t possible_keys[TRIAL_NUM][AES_128_KEY_SIZE];
    uint8_t master_key[AES_128_KEY_SIZE];
    uint8_t ekey[AES_128_KEY_SIZE * 2];
    int nk, pk;

    fetch_random_key(master_key);
    printf("Fetched a random key for encryption.\n");
    printf("Master key : ");
    printf("\033[0;32m");
    print_vect(master_key, AES_128_KEY_SIZE);
    printf("\033[0m");
    for (i = 0; i < TRIAL_NUM; i++)
    {
        generate_set(set, (i * 52) % 256); // (i * 52) % 256 random constant (in the set) value.
        for (j = 0; j < 256; j++)
        {
            aes128_enc(set[j], master_key, 4, 0);
        }
        compute_possible_key(set, possible_keys[i]);
    }

    printf("%d Delta sets were encrypted, encrypted them,\nand %d possible keys were computed.\n", TRIAL_NUM, TRIAL_NUM);
    printf("Will now deduce the actual master key ...\n");
    nk = 0;
    pk = 16;
    for (i = 0; i < AES_128_KEY_SIZE; i++)
    {
        ekey[i + nk] = max_repeating_byte(possible_keys, i);
    }

    nk = 16;
    pk = 0;

    for (i = 0; i < 4; i++)
    {
        pk = (pk + 16) & 0x10;
        nk = (nk + 16) & 0x10;
        prev_aes128_round_key(ekey + nk, ekey + pk, 3 - i);
    }

    if (strncmp((const char *)master_key, (const char *)(ekey + pk), AES_128_KEY_SIZE) == 0)
    {
        printf("\033[0;32m");
        printf("Master key found.\n");
        printf("\033[0m");
        printf("Found key : ");
        printf("\033[0;31m");
        print_vect(ekey + pk, AES_128_KEY_SIZE);
        printf("\033[0m");
        printf("Master key randomly generated and found key are identical.\n");
        printf("Attack successful.\n");
        printf("\033[0m");
        return 0;
    }
    return 1;
}
