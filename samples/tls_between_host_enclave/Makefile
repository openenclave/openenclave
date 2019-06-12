# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

.PHONY: all build clean run

all: build

build:
	$(MAKE) -C server
	$(MAKE) -C client
clean:
	$(MAKE) -C server clean
	$(MAKE) -C client clean


run:
	./server/host/tls_server_host ./server/enc/tls_server_enc.signed -port:12341 &
	sleep 2
	./client/tls_client -server:localhost -port:12341
