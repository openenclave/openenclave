# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.

.PHONY: all build clean run simulate

OE_CRYPTO_LIB := mbedtls
export OE_CRYPTO_LIB

all: build

build:
	$(MAKE) -C enclave
	$(MAKE) -C host

clean:
	$(MAKE) -C enclave clean
	$(MAKE) -C host clean

run:
	host/allocator_demo_host ./enclave/enclave_default.signed ./enclave/enclave_custom.signed

simulate:
	host/allocator_demo_host ./enclave/enclave_default.signed ./enclave/enclave_custom.signed --simulate
