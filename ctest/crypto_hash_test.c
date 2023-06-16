/*
 * Copyright (c) 2021-2031, Jinping Wu (wunekky@gmail.com). All rights reserved.
 *
 * SPDX-License-Identifier: MIT
 */

#include <stdio.h>
#include <sys/types.h>
#include <unistd.h>
#include <errno.h>
#include <sys/socket.h>
#include <linux/if_alg.h>
#include <assert.h>
#include "crypto_data.h"
#include "crypto_util.h"
#include "crypto_hash_test.h"

# include <openssl/sha.h>
#include <openssl/err.h>
#include <openssl/evp.h>

#if 0
/* deprecated: Since OpenSSL 3.0 */
void sha256_test_old(void) {

    int status;
    unsigned char md[SHA256_DIGEST_LENGTH];
    SHA256_CTX c;

    SHA256_Init(&c);

    SHA256_Update(&c, sha256_msg, sizeof(sha256_msg));

    SHA256_Final(md, &c);

    memory_hex_dump("hashed message", md, SHA256_DIGEST_LENGTH);
    status =  hex_compare(md, sha256_digest, SHA256_DIGEST_LENGTH);
    if (status < 0)
        printf(RED"[%-50s] FAIL\n"COLOR_NONE, __func__);
    else
        printf(GREEN"[%-50s] SUCCESS\n"COLOR_NONE, __func__);

}
#endif

/* refer to: demos/digest/EVP_MD_demo.c */
void sha256_test(void) {
    int status;
    OSSL_LIB_CTX *library_context;
    const char *option_properties = NULL;
    EVP_MD *message_digest = NULL;
    EVP_MD_CTX *digest_context = NULL;
    unsigned int digest_length;
    unsigned char *digest_value = NULL;

    library_context = OSSL_LIB_CTX_new();
    if (library_context == NULL) {
        fprintf(stderr, "OSSL_LIB_CTX_new() returned NULL\n");
        goto cleanup;
    }

    /*
     * Fetch a message digest by name
     * The algorithm name is case insensitive. 
     * See providers(7) for details about algorithm fetching
     */
    message_digest = EVP_MD_fetch(library_context,
                                  "SHA2-256", option_properties);
    if (message_digest == NULL) {
        fprintf(stderr, "EVP_MD_fetch could not find SHA2-256.");
        goto cleanup;
    }

    /* Determine the length of the fetched digest type */
    digest_length = EVP_MD_get_size(message_digest);
    if (digest_length <= 0) {
        fprintf(stderr, "EVP_MD_get_size returned invalid size.\n");
        goto cleanup;
    }

    digest_value = OPENSSL_malloc(digest_length);
    if (digest_value == NULL) {
        fprintf(stderr, "No memory.\n");
        goto cleanup;
    }

    /*
     * Make a message digest context to hold temporary state
     * during digest creation
     */
    digest_context = EVP_MD_CTX_new();
    if (digest_context == NULL) {
        fprintf(stderr, "EVP_MD_CTX_new failed.\n");
        goto cleanup;
    }

    /*
     * Initialize the message digest context to use the fetched 
     * digest provider
     */
    if (EVP_DigestInit(digest_context, message_digest) != 1) {
        fprintf(stderr, "EVP_DigestInit failed.\n");
        goto cleanup;
    }
    /* Digest parts one and two of the soliloqy */
    if (EVP_DigestUpdate(digest_context, sha256_msg, sizeof(sha256_msg)) != 1) {
        fprintf(stderr, "EVP_DigestUpdate(hamlet_1) failed.\n");
        goto cleanup;
    }
    if (EVP_DigestFinal(digest_context, digest_value, &digest_length) != 1) {
        fprintf(stderr, "EVP_DigestFinal() failed.\n");
        goto cleanup;
    }




    memory_hex_dump("hashed message", digest_value, digest_length);
    status =  hex_compare(digest_value, sha256_digest, digest_length);
    if (status < 0)
        printf(RED"[%-50s] FAIL\n"COLOR_NONE, __func__);
    else
        printf(GREEN"[%-50s] SUCCESS\n"COLOR_NONE, __func__);

cleanup:
    /* OpenSSL free functions will ignore NULL arguments */
    EVP_MD_CTX_free(digest_context);
    OPENSSL_free(digest_value);
    EVP_MD_free(message_digest);

    OSSL_LIB_CTX_free(library_context);
}


void crypto_hash_test(void) {
#if CONFIG_HASH_SHA256 == 1
    //sha256_test_old();
    sha256_test();
#endif
}