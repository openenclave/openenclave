# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

.PHONY: all build clean run

all: build

build:
	$(MAKE) -C tls_between_enclaves 
	$(MAKE) -C tls_between_non_enclave_enclave

clean:
	$(MAKE) -C tls_between_enclaves clean
	$(MAKE) -C tls_between_non_enclave_enclave clean

run:
	$(MAKE) -C tls_between_enclaves run
	$(MAKE) -C tls_between_non_enclave_enclave run
