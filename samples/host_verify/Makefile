# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.

include ../config.mk

CFLAGS=$(shell pkg-config oehost-$(COMPILER) --cflags)
LDFLAGS=$(shell pkg-config oehost-$(COMPILER) --libs)

EXISTS_FILE=0
EXISTS_SGX_CERT_EC=0
EXISTS_SGX_CERT_RSA=0
EXISTS_SGX_REPORT=0

ifneq ($(wildcard sgx_cert_ec.der),)
	EXISTS_SGX_CERT_EC=1
	EXISTS_FILE=1
endif

ifneq ($(wildcard sgx_cert_rsa.der),)
	EXISTS_SGX_CERT_RSA=1
	EXISTS_FILE=1
endif

ifneq ($(wildcard sgx_report.bin),)
	EXISTS_SGX_REPORT=1
	EXISTS_FILE=1
endif

.PHONY: all build clean run

all: build

build:
	@ echo "Compilers used: $(CC), $(CXX)"
	$(CC) -g -c $(CFLAGS) host.c
	$(CC) -o host_verify host.o $(LDFLAGS)

clean:
	rm -f host_verify host.o

run:
ifeq ($(EXISTS_FILE), 0)
	./host_verify -h
endif
ifeq ($(EXISTS_SGX_CERT_EC), 1)
	./host_verify -c sgx_cert_ec.der
endif
ifeq ($(EXISTS_SGX_CERT_RSA), 1)
	./host_verify -c sgx_cert_rsa.der
endif
ifeq ($(EXISTS_SGX_REPORT), 1)
	./host_verify -r sgx_report.bin
endif
