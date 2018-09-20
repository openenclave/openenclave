# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

OPENENCLAVE_CONFIG=../../config.mak
include $(OPENENCLAVE_CONFIG)

all: build

# C++ build environment setup
CXX = clang++-7
CXXFLAGS += -Wall  -std=c++11
CXXFLAGS += -mllvm -x86-speculative-load-hardening
INCLUDES = -I$(OE_INCLUDEDIR)

# C build environment setup
CC = clang-7
CFLAGS += -Wall -Werror -m64 -nostdinc -fPIC
CFLAGS += -mllvm -x86-speculative-load-hardening
CINCLUDES += -I$(OE_INCLUDEDIR)
CINCLUDES += -I$(OE_INCLUDEDIR)/libc

LDFLAGS += -rdynamic

LIBRARIES += -L$(OE_LIBDIR)/openenclave/host
LIBRARIES += -loehost
LIBRARIES += -lcrypto
LIBRARIES += -lpthread
LIBRARIES += -ldl
LIBRARIES += -lsgx_enclave_common
LIBRARIES += -lsgx_ngsa_ql
LIBRARIES += -lsgx_urts_ng

build:
	$(OE_BINDIR)/oeedger8r ../remoteattestation.edl --untrusted
	$(CC) -c $(CFLAGS) $(CINCLUDES) remoteattestation_u.c 
	$(CXX) -c $(CXXFLAGS) $(INCLUDES) host.cpp
	$(CXX) -o attestation_host host.o remoteattestation_u.o $(LDFLAGS) $(LIBRARIES)

clean:
	rm -f attestation_host *.o remoteattestation_u.*  remoteattestation_args.h



