# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

OPENENCLAVE_CONFIG=../../config.mak
include $(OPENENCLAVE_CONFIG)

all: build

CXXFLAGS=-Wall -g -std=c++11

INCLUDES = -I$(OE_INCLUDEDIR)

LDFLAGS += -rdynamic

LIBRARIES += -L$(OE_LIBDIR)/openenclave/host
LIBRARIES += -loehost
LIBRARIES += -lcrypto
LIBRARIES += -lpthread
LIBRARIES += -ldl
LIBRARIES += -lsgx_enclave_common
LIBRARIES += -lsgx_dcap_ql
LIBRARIES += -lsgx_urts

build:
	g++ -c $(CXXFLAGS) $(INCLUDES) host.cpp ecalls.cpp
	g++ -o attestation_host host.o ecalls.o $(LDFLAGS) $(LIBRARIES)

clean:
	rm -f attestation_host host.o

