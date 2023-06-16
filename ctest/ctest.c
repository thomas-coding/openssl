/*
 * Copyright (c) 2021-2031, Jinping Wu (wunekky@gmail.com). All rights reserved.
 *
 * SPDX-License-Identifier: MIT
 */

#include <stdio.h>
#include <sys/types.h>
#include <unistd.h>
#include <errno.h>
#include "crypto_hash_test.h"

int main(void)
{
	printf("=== Crypto Test Begin ===\n");
	printf("\n");

	crypto_hash_test();
#if 0
	crypto_aes_test();
	crypto_rsa_test();
	crypto_ecc_test();
	crypto_hmac_test();
	crypto_chachapoly_test();
#endif

	printf("\n");
	printf("=== Crypto Test End ===\n");
	return 0;
}
