# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.

.PHONY: all build clean run simulate

# Set OE_CRYPTO_LIB as "mbedtls" or "openssl", to use the respective cryptolibs
OE_CRYPTO_LIB := mbedtls
export OE_CRYPTO_LIB

SAMPLE_CRYPTO_SRC := "$(OE_CRYPTO_LIB)src"
export SAMPLE_CRYPTO_SRC

all: build

build:
	$(MAKE) -C enclave
	$(MAKE) -C host

clean:
	$(MAKE) -C enclave clean
	$(MAKE) -C host clean

run:
	host/file-encryptorhost testfile ./enclave/file-encryptorenc.signed

simulate:
	host/file-encryptorhost testfile ./enclave/file-encryptorenc.signed --simulate

