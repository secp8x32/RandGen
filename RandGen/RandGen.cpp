#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/evp.h>
#include <openssl/ec.h>
#include <openssl/bn.h>
#include <openssl/rand.h>

int main(int argc, char** argv)
{
	if (argc != 3) {
		printf("usage:");
		printf("%s num_keys out_file", argv[0]);
		exit(-1);
	}
	size_t total_keys = atoll(argv[1]);
	const char* out_file = argv[2];

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
