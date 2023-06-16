#!/bin/bash

# shell folder
shell_folder=$(cd "$(dirname "$0")" || exit;pwd)

# Build openssl lib
make clean
./Configure --debug
make -j8

# Build mbedtls test
rm -rf ${shell_folder}/mytest/ctest

gcc -g -static -o ctest/ctest ctest/ctest.c \
    ctest/crypto_data.c ctest/crypto_util.c \
    ctest/crypto_hash_test.c \
	-L ${shell_folder}/ -lssl -lcrypto -lpthread -ldl \
	-I ${shell_folder}/include

#rm -rf ${shell_folder}/ctest/ctest.asm
#objdump -xdS ${shell_folder}/ctest/ctest > ${shell_folder}/ctest/ctest.asm
