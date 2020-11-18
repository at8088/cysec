#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <math.h>
#include <time.h> /*time() & difftime() to quit if search is too long*/

#include "uthash.h"				/*hash table*/
#include "xoshiro256starstar.h" /*pseudo random gen*/

#define ROTL24_16(x) ((((x) << 16) ^ ((x) >> 8)) & 0xFFFFFF)
#define ROTL24_3(x) ((((x) << 3) ^ ((x) >> 21)) & 0xFFFFFF)

#define ROTL24_8(x) ((((x) << 8) ^ ((x) >> 16)) & 0xFFFFFF)
#define ROTL24_21(x) ((((x) << 21) ^ ((x) >> 3)) & 0xFFFFFF)

#define IV 0x010203040506ULL
#define N (1 << 18)

typedef struct _htable
{
	uint64_t h;		   /*plays the role of the key*/
	uint32_t m1[4];	   /*the message*/
	UT_hash_handle hh; /*makes the struct hashable*/
} htable_t;

uint64_t cs48_dm(const uint32_t m[4], const uint64_t h);

// void add_random_message(htable_t *ht)
// {
// 	htable_t *p = (htable_t *)malloc(sizeof(*p));
// 	htable_t *check = NULL;
// 	for (int j = 0; j < 4; j++)
// 	{
// 		p->m1[j] = (uint32_t)(xoshiro256starstar_random() & 0xFFFFFF);
// 	}
// 	p->h = cs48_dm(p->m1, 0);
// 	HASH_FIND(hh, ht, &(p->h), sizeof(uint64_t), check);
// 	if (check == NULL)
// 	{
// 		HASH_ADD(hh, ht, h, sizeof(uint64_t), p);
// 	}
// 	return;
// }

void delete_all(htable_t *ht)
{
	htable_t *current_msg, *tmp;
	HASH_ITER(hh, ht, current_msg, tmp)
	{
		HASH_DEL(ht, current_msg);
		free(current_msg);
	}
}

/*
 * the 96-bit key is stored in four 24-bit chunks in the low bits of k[0]...k[3]
 * the 48-bit plaintext is stored in two 24-bit chunks in the low bits of p[0], p[1]
 * the 48-bit ciphertext is written similarly in c
 */
void speck48_96(const uint32_t k[4], const uint32_t p[2], uint32_t c[2])
{
	uint32_t rk[23];
	uint32_t ell[3] = {k[1], k[2], k[3]};

	rk[0] = k[0];

	c[0] = p[0];
	c[1] = p[1];

	/* full key schedule */
	for (unsigned i = 0; i < 22; i++)
	{
		uint32_t new_ell = ((ROTL24_16(ell[0]) + rk[i]) ^ i) & 0xFFFFFF; // addition (+) is done mod 2**24
		rk[i + 1] = ROTL24_3(rk[i]) ^ new_ell;
		ell[0] = ell[1];
		ell[1] = ell[2];
		ell[2] = new_ell;
	}

	for (unsigned i = 0; i < 23; i++)
	{
		c[0] = ((ROTL24_16(c[0]) + c[1]) & 0xFFFFFF) ^ rk[i];
		c[1] = ROTL24_3(c[1]) ^ c[0];
	}

	return;
}

int test_sp48(void)
{
	uint32_t k[4] = {0x020100, 0x0a0908, 0x121110, 0x1a1918};
	uint32_t p[2] = {0x6d2073, 0x696874};
	uint32_t expected_cipher[2] = {0x735e10, 0xb6445d};
	uint32_t c[2];
	speck48_96(k, p, c);
	int is_ok = 1;
	for (int i = 0; i < 2; i++)
	{
		if (c[i] != expected_cipher[i])
			is_ok = 0;
	}
	return is_ok;
}

/* the inverse cipher */
void speck48_96_inv(const uint32_t k[4], const uint32_t c[2], uint32_t p[2])
{
	uint32_t rk[23];
	uint32_t ell[3] = {k[1], k[2], k[3]};

	rk[0] = k[0];

	p[0] = c[0];
	p[1] = c[1];
	for (unsigned i = 0; i < 22; i++)
	{
		uint32_t new_ell = ((ROTL24_16(ell[0]) + rk[i]) ^ i) & 0xFFFFFF; // addition (+) is done mod 2**24
		rk[i + 1] = ROTL24_3(rk[i]) ^ new_ell;
		ell[0] = ell[1];
		ell[1] = ell[2];
		ell[2] = new_ell;
	}
	for (unsigned i = 0; i < 23; i++)
	{
		p[1] = ROTL24_21(p[1] ^ p[0]);
		p[0] = ROTL24_8(((p[0] ^ rk[23 - i - 1]) - p[1]) & 0xFFFFFF);
	}
}

int test_sp48_inv(void)
{
	uint32_t k[4] = {0x020100, 0x0a0908, 0x121110, 0x1a1918};
	uint32_t expected_plain[2] = {0x6d2073, 0x696874};
	uint32_t c[2] = {0x735e10, 0xb6445d};
	uint32_t p[2];
	int is_ok = 1;
	speck48_96_inv(k, c, p);
	for (int i = 0; i < 2; i++)
	{
		if (p[i] != expected_plain[i])
			is_ok = 0;
	}
	return is_ok;
}

/* The Davies-Meyer compression function based on speck48_96,
 * using an XOR feedforward
 * The input/output chaining value is given on the 48 low bits of a single 64-bit word,
 * whose 24 lower bits are set to the low half of the "plaintext"/"ciphertext" (p[0]/c[0])
 * and whose 24 higher bits are set to the high half (p[1]/c[1])
 */
uint64_t cs48_dm(const uint32_t m[4], const uint64_t h)
{
	uint32_t c[2];
	uint32_t p[2] = {h & 0xFFFFFF, (h >> 24) & 0xFFFFFF};
	uint64_t ret = 0;
	speck48_96(m, p, c);
	ret = (uint64_t)c[0];
	ret |= (uint64_t)c[1] << 24;
	return ret ^ h;
}

int test_cs48_dm()
{
	uint32_t k[4] = {0, 0, 0, 0};
	uint64_t r = cs48_dm(k, (uint64_t)0);

	return r == 0x7FDD5A6EB248ULL;
}

/* assumes message length is fourlen * four blocks of 24 bits, each stored as the low bits of 32-bit words
 * fourlen is stored on 48 bits (as the 48 low bits of a 64-bit word)
 * when padding is include, simply adds one block (96 bits) of padding with fourlen and zeros on higher pos */
uint64_t hs48(const uint32_t *m, uint64_t fourlen, int padding, int verbose)
{
	uint64_t h = IV;
	const uint32_t *mp = m;

	for (uint64_t i = 0; i < fourlen; i++)
	{
		h = cs48_dm(mp, h);
		if (verbose)
			printf("@%llu : %06X %06X %06X %06X => %06llX\n", i, mp[0], mp[1], mp[2], mp[3], h);
		mp += 4;
	}
	if (padding)
	{
		uint32_t pad[4];
		pad[0] = fourlen & 0xFFFFFF;
		pad[1] = (fourlen >> 24) & 0xFFFFFF;
		pad[2] = 0;
		pad[3] = 0;
		h = cs48_dm(pad, h);
		if (verbose)
			printf("@%llu : %06X %06X %06X %06X => %06llX\n", fourlen, pad[0], pad[1], pad[2], pad[3], h);
	}

	return h;
}

/* Computes the unique fixed-point for cs48_dm for the message m */
uint64_t get_cs48_dm_fp(uint32_t m[4])
{
	uint64_t fp = 0;
	uint32_t c[2] = {0, 0};
	uint32_t p[2] = {0, 0};
	speck48_96_inv(m, c, p);
	fp = (uint64_t)p[0];
	fp |= (uint64_t)p[1] << 24;
	return fp;
}

int test_cs48_dm_fp(void)
{
	uint32_t m[4] = {0x020100, 0x0a0908, 0x121110, 0x1a1918};
	uint64_t fp = get_cs48_dm_fp(m);
	uint64_t c = cs48_dm(m, fp);
	return c == fp;
}

/* Finds a two-block expandable message for hs48, using a fixed-point
 * That is, computes m1, m2 s.t. hs48_nopad(m1||m2) = hs48_nopad(m1||m2^*),
 * where hs48_nopad is hs48 with no padding */
void find_exp_mess(uint32_t m1[4], uint32_t m2[4])
{
	time_t tm, tm_plus_3mn;
	htable_t *ht = NULL; // head of the hash table
	htable_t *check = NULL;
	uint64_t seed[4] = {56995656, 69996, 848484, 78954};
	xoshiro256starstar_random_set(seed);
	for (int i = 0; i < N; i++)
	{
		htable_t *p = (htable_t *)malloc(sizeof(*p));
		for (int j = 0; j < 4; j++)
		{
			p->m1[j] = (uint32_t)(xoshiro256starstar_random() & 0xFFFFFF);
		}
		p->h = cs48_dm(p->m1, IV);
		HASH_FIND(hh, ht, &(p->h), sizeof(uint64_t), check); // not probable
		if (check == NULL)
		{
			HASH_ADD(hh, ht, h, sizeof(uint64_t), p);
		}
		else
		{
			// highly unlikely that this happens
			printf("Possible collision in find_exp_mess().")
		}

		check = NULL;
	}
	time(&tm);
	while (1)
	// for (int i = 0; i < (); i++)
	{
		time(&tm_plus_3mn);
		uint32_t m[4];
		for (int j = 0; j < 4; j++)
		{
			m[j] = (uint32_t)(xoshiro256starstar_random() & 0xFFFFFF);
		}
		uint64_t fp = get_cs48_dm_fp(m);
		HASH_FIND(hh, ht, &fp, sizeof(uint64_t), check);
		if (check != NULL)
		{
			for (int i = 0; i < 4; i++)
			{
				m1[i] = check->m1[i];
				m2[i] = m[i];
			}
			break;
		}
		if ((difftime(tm_plus_3mn, tm) / 60) > 3.0)
		{
			// if the search takes more than 3 mn
			// quit and free memory
			printf("Search for collision took too long. Quiting now to free memory.\n");
			break;
		}
	}
	delete_all(ht);
}

void attack(void)
{
	/* FILL ME */
}

/**	m1 = {0x50145f, 0x8e50f9, 0x3a7e85, 0x64c6ae}
	m2 = {0x5796c7, 0xd6aad7, 0xb046, 0x7e0653}
	found in 51s
*/
int main()
{
	// attack();
	// int a = test_sp48();
	// int b = test_sp48_inv();
	// int c = test_cs48_dm();
	// int d = test_cs48_dm_fp();
	// printf("%d    %d    %d    %d\n", a, b, c, d);

	return 0;
}
