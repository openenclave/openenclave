# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.

all: build

build:
	$(MAKE) -C enc/${OE_CRYPTO_LIB}
	$(MAKE) -C host

clean:
	$(MAKE) -C enc/${OE_CRYPTO_LIB} clean
	$(MAKE) -C host clean

run:
	host/tls_server_host ./enc/${OE_CRYPTO_LIB}/tls_server_enc.signed -port:12341
