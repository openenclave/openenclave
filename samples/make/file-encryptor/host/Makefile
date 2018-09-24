# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

OPENENCLAVE_CONFIG=../../config.mak
include $(OPENENCLAVE_CONFIG)

all: build

# C++ build environment setup
CXX = clang++-7
CXXFLAGS += -Wall -g -std=c++11
CXXFLAGS += -mllvm -x86-speculative-load-hardening
INCLUDES = -I$(OE_INCLUDEDIR)

# C build environment setup
CC = clang-7
CFLAGS += -Wall -Werror -O2 -m64 -nostdinc -fPIC
CFLAGS += -mllvm -x86-speculative-load-hardening
CINCLUDES += -I$(OE_INCLUDEDIR)
CINCLUDES += -I$(OE_INCLUDEDIR)/libc

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
LIBRARIES += $(call optlib,sgx_dcap_ql)
LIBRARIES += $(call optlib,sgx_urts)

build:
	$(OE_BINDIR)/oeedger8r ../fileencryptor.edl --untrusted
	$(CXX) -c $(CXXFLAGS) $(INCLUDES) host.cpp
	$(CC) -c $(CFLAGS) $(CINCLUDES) fileencryptor_u.c 
	$(CXX) -o file-encryptorhost host.o fileencryptor_u.o $(LDFLAGS) $(LIBRARIES)


clean:
	rm -f file-encryptorhost fileencryptor_u.* fileencryptor_args.h *.o

