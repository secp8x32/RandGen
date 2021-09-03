#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/evp.h>
#include <openssl/ec.h>
#include <openssl/bn.h>
#include <openssl/rand.h>
#include <openssl/sha.h>
#include "uint256.h"

void RandAddSeed(bool fPerfmon = false);
__int64 GetTime();

int main(int argc, char** argv)
{
	if (argc != 3) {
		printf("usage:");
		printf("%s num_keys out_file", argv[0]);
		exit(-1);
	}
	size_t total_keys = atoll(argv[1]);
	const char* out_file = argv[2];

	// Seed random number generator with screen scrape and other hardware sources
	RAND_screen();

	// Seed random number generator with perfmon data
	RandAddSeed(true);

	BN_CTX* bn_ctx = BN_CTX_new();
	BIGNUM* curve_order = BN_new();
	BIGNUM* priv_key = BN_new();
	EC_KEY* ec_key = EC_KEY_new_by_curve_name(NID_secp256k1);
	const EC_GROUP* group = EC_KEY_get0_group(ec_key);
	EC_GROUP_get_order(group, curve_order, bn_ctx);

	FILE* file = fopen(out_file, "a");

	for (size_t n = 0; n < total_keys; n++) {
		BN_rand_range(priv_key, curve_order);
		unsigned char bytes[32];
		BN_bn2bin(priv_key, bytes);
		//fprintf(file, "0x");
		for (int i = 0; i < 32; i++) {
			fprintf(file, "%02x", bytes[i]);
		}
		fprintf(file, "\n");
		if (n % 10000 == 0) {
			printf("\rcompleted: %lf %%", (double)n / (double)total_keys * 100.0);
			fflush(stdout);
		}
	}

	fclose(file);
	EC_KEY_free(ec_key);
	BN_CTX_free(bn_ctx);
	BN_free(curve_order);
	BN_free(priv_key);
	return 0;
}


void RandAddSeed(bool fPerfmon)
{
	// Seed with CPU performance counter
	LARGE_INTEGER PerformanceCount;
	QueryPerformanceCounter(&PerformanceCount);
	RAND_add(&PerformanceCount, sizeof(PerformanceCount), 1.5);
	memset(&PerformanceCount, 0, sizeof(PerformanceCount));

	static __int64 nLastPerfmon;
	if (fPerfmon || GetTime() > nLastPerfmon + 5 * 60)
	{
		nLastPerfmon = GetTime();

		// Seed with the entire set of perfmon data
		unsigned char pdata[250000];
		memset(pdata, 0, sizeof(pdata));
		unsigned long nSize = sizeof(pdata);
		long ret = RegQueryValueEx(HKEY_PERFORMANCE_DATA, L"Global", NULL, NULL, pdata, &nSize);
		RegCloseKey(HKEY_PERFORMANCE_DATA);
		if (ret == ERROR_SUCCESS)
		{
			uint256 hash;
			SHA256(pdata, nSize, (unsigned char*)&hash);
			RAND_add(&hash, sizeof(hash), min(nSize / 500.0, (double)sizeof(hash)));
			hash = 0;
			memset(pdata, 0, nSize);
			printf("RandAddSeed() got %d bytes of performance data\n", nSize);
		}
	}
}


__int64 GetTime()
{
	return time(NULL);
}