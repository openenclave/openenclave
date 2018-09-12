# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

OPENENCLAVE_CONFIG=../../config.mak
include $(OPENENCLAVE_CONFIG)

all: build

CXX = clang++-7

CXXFLAGS += -Wall -g -std=c++11
CXXFLAGS += -mllvm -x86-speculative-load-hardening

INCLUDES = -I$(OE_INCLUDEDIR)

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
	$(CXX) -c $(CXXFLAGS) $(INCLUDES) host.cpp ecalls.cpp
	$(CXX) -o attestation_host host.o ecalls.o $(LDFLAGS) $(LIBRARIES)

clean:
	rm -f attestation_host host.o

