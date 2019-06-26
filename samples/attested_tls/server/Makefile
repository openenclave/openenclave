# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

all: build

build:
	$(MAKE) -C enc
	$(MAKE) -C host

clean:
	$(MAKE) -C enc clean
	$(MAKE) -C host clean

run:
	host/tls_server_host ./enc/tls_server_enc.signed -port:12341
