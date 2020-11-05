#ifndef ATTACK_H
#define ATTACK_H
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include "aes-128_enc.h"

#define TRIAL_NUM 20

void query_3_and_half(uint8_t set[256][16], uint8_t key[AES_128_KEY_SIZE]);
void fetch_random_key(uint8_t *key);
uint8_t half_round_decrypt(uint8_t state[AES_BLOCK_SIZE], int index, uint8_t key_byte);
int modular_substraction_16(int x, int y);
void generate_set(uint8_t set[256][AES_BLOCK_SIZE], uint8_t c);
void compute_possible_key(uint8_t enc_set[256][AES_BLOCK_SIZE], uint8_t result_key[AES_128_KEY_SIZE]);
int attack();

#endif // ATTACK_H
