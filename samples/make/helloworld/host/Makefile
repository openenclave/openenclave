# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

OPENENCLAVE_CONFIG=../../config.mak
include $(OPENENCLAVE_CONFIG)

all: build

CFLAGS=-Wall -g

INCLUDES = -I$(OE_INCLUDEDIR)
LDFLAGS += -rdynamic

LIBRARIES += -L$(OE_LIBDIR)/openenclave/host
LIBRARIES += -loehost
LIBRARIES += -lcrypto
LIBRARIES += -lpthread
LIBRARIES += -ldl

# To make this Makefile support building an
# enclave library for both SGX1 and SGX+FLC systems,
# the optlib was defined to help optionally
# link the following Intel SGX libraries, which
# are needed only for building enclaves library
# for SGX+FLC systems

define optlib
$(patsubst /usr/lib/x86_64-linux-gnu/lib%.so,-l%,$(wildcard /usr/lib/x86_64-linux-gnu/lib$(1).so))
endef
LIBRARIES += $(call optlib,sgx_enclave_common)
LIBRARIES += $(call optlib,sgx_ngsa_ql)
LIBRARIES += $(call optlib,sgx_urts_ng)

build:
	gcc -c $(CFLAGS) $(INCLUDES) host.c
	gcc -o helloworldhost host.o $(LDFLAGS) $(LIBRARIES)

clean:
	rm -f helloworldhost host.o

