# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.

all: build

build:
	$(MAKE) -C enc
	$(MAKE) -C host

clean:
	$(MAKE) -C enc clean
	$(MAKE) -C host clean

run:
	host/tls_client_host ./enc/tls_client_enclave.signed -server:localhost -port:12341
