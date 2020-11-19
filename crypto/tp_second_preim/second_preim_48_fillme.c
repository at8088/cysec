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
#define N (1 << 24)
#define MAX_WAITING_TIME_FOR_ATTACK 10.0
#define MAX_WAITING_TIME_FOR_EM_SEARCH 1.0

// hash table type (cf. http://troydhanson.github.com/uthash/ for documentaion)
typedef struct _htable
{
	uint64_t h;		   /*plays the role of the key*/
	uint32_t m1[4];	   /*the message*/
	int index_in_mess; /*index of the block in the message mess (only used for the func attack*/
	UT_hash_handle hh; /*makes the struct hashable*/
} htable_t;

uint64_t cs48_dm(const uint32_t m[4], const uint64_t h);

/*Deletes and frees memory allocated for the hash table*/
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
/*returns 1 if the encryption is correct 0 otherwise*/
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
/*returns 1 if the decryption is correct 0 otherwise*/
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
/*returns 1 if the compression function is correct 0 otherwise*/
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
/*returns 1 if the fixed point computaion is correct 0 otherwise*/
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
	time_t tm, tm_plus_1mn;
	htable_t *ht = NULL; // head of the hash table
	htable_t *check = NULL;
	// uint64_t seed[4] = {0x121fffe3216, 0x4defefffef, 0xfff575ea2, 69};
	// xoshiro256starstar_random_set(seed);
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

		check = NULL;
	}
	time(&tm);
	while (1)
	{
		time(&tm_plus_1mn);
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
		if ((difftime(tm_plus_1mn, tm) / 60) > MAX_WAITING_TIME_FOR_EM_SEARCH)
		{
			// if the search takes more than 1 mn
			// quit and free memory
			printf("Search for collision took too long. Quiting now to free memory.\n");
			break;
		}
	}
	delete_all(ht);
}

int test_em()
{
	uint32_t m1[4];
	uint32_t m2[4];
	find_exp_mess(m1, m2);
	uint64_t fp = get_cs48_dm_fp(m2);
	uint64_t h = cs48_dm(m1, IV);
	uint32_t m[16];
	for (size_t i = 0; i < 4; i++)
	{
		m[i] = m1[i];
	}
	for (size_t i = 4; i < 16; i += 4)
	{
		m[i + 0] = m2[0];
		m[i + 1] = m2[1];
		m[i + 2] = m2[2];
		m[i + 3] = m2[3];
	}

	uint64_t b = hs48(m, 4, 0, 0);

	return b == h && h == fp;
}

void attack(void)
{
	// uint32_t m1[4], m2[4];

	//For testing
	uint32_t m1[4] = {0x248bc5, 0xbb0e8c, 0x3628e0, 0x294226};
	uint32_t m2[4] = {0xd5662d, 0x2651d1, 0x3eb0f4, 0xaa4d89};

	uint64_t fp = 0;
	uint32_t *mess = NULL, *mess2 = NULL;
	htable_t *p = NULL, *ht = NULL;
	uint64_t chaining_val = IV;
	int cm_index = 0;
	uint32_t cm[4] = {0, 0, 0, 0};
	int cm_found = 0;
	time_t tm, tm_plus_10mn;

	mess = (uint32_t *)malloc(sizeof(*mess) * (1 << 20));
	if (mess == NULL)
	{
		printf("Couldn't allocate the memory for mess. Exiting.");
		exit(1);
	}
	for (uint64_t i = 0; i < (1 << 20); i += 4)
	{
		mess[i + 0] = i;
		mess[i + 1] = 0;
		mess[i + 2] = 0;
		mess[i + 3] = 0;

		p = (htable_t *)malloc(sizeof(*p));
		p->h = cs48_dm((mess + i), chaining_val);
		p->index_in_mess = i;
		chaining_val = p->h;
		HASH_ADD(hh, ht, h, sizeof(uint64_t), p);
	}
	printf("%llx\n", p->h);
	// find_exp_mess(m1, m2);
	fp = get_cs48_dm_fp(m2);
	time(&tm);
	p = NULL;
	while (1)
	{
		time(&tm_plus_10mn);
		for (int i = 0; i < 4; i++)
		{
			cm[i] = (uint32_t)(xoshiro256starstar_random() & 0xFFFFFF);
		}
		chaining_val = cs48_dm(cm, fp);
		HASH_FIND(hh, ht, &chaining_val, sizeof(uint64_t), p);
		if (p != NULL)
		{
			printf("cm found.\n");
			cm_found = 1;
			cm_index = p->index_in_mess;
			break;
		}
		if ((difftime(tm_plus_10mn, tm) / 60) > MAX_WAITING_TIME_FOR_ATTACK)
		{
			printf("Collision block not found. Exiting to free memory.");
			cm_found = 0;
			break;
		}
	}

	delete_all(ht);

	/*constructiong mess2*/
	if (cm_found)
	{
		printf("fp = %llx, index = %llu\n", fp, cm_index);
		mess2 = (uint32_t *)malloc(sizeof(*mess) * (1 << 20));
		if (mess2 == NULL)
		{
			printf("Couldn't allocate the memory for mess2. Exiting.");
			free(mess);
			exit(1);
		}

		for (size_t i = 0; i < 4; i++)
		{
			mess2[i] = m1[i];
		}

		for (uint64_t i = 4; i < (cm_index); i += 4)
		{
			mess2[i + 0] = m2[0];
			mess2[i + 1] = m2[1];
			mess2[i + 2] = m2[2];
			mess2[i + 3] = m2[3];
		}

		for (uint64_t i = 0; i < 4; i++)
		{
			mess2[cm_index + i] = cm[i];
		}

		for (uint64_t i = (cm_index) + 4; i < (1 << 20); i++)
		{
			mess2[i] = mess[i];
		}
		uint64_t g = hs48(mess2, (1 << 18), 1, 0);
		printf("g = %llx\n", g);
	}
	free(mess2);
	free(mess);
}

int main()
{

	if (test_sp48())
		printf("Speck 48/96 encryption test successful.\n");
	if (test_sp48_inv())
		printf("Speck 48/96 decryption test successful.\n");
	if (test_cs48_dm())
		printf("Davies-Meyer compression function test successful.\n");
	if (test_cs48_dm_fp())
		printf("Fixed point computation test successful.\n");
	if (test_em())
		printf("Expandable message computation test successful.\n");
	// attack();

	return 0;
}
