# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

# Detect C and C++ compiler options
# if not gcc and g++, default to clang-7
C_COMPILER=$(notdir $(CC))
ifeq ($(C_COMPILER), gcc)
        CXX_COMPILER=$(notdir $(CXX))
        USE_GCC = true
endif

ifeq ($(USE_GCC),)
        CC = clang-7
        CXX = clang++-7
        C_COMPILER=clang
        CXX_COMPILER=clang++
endif

CFLAGS=$(shell pkg-config oeenclave-$(C_COMPILER) --cflags)
CXXFLAGS=$(shell pkg-config oeenclave-$(CXX_COMPILER) --cflags)
LDFLAGS=$(shell pkg-config oeenclave-$(CXX_COMPILER) --libs)

all:
	$(MAKE) build
	$(MAKE) sign

build:
	@ echo "Compiler used: $(CC)"
	oeedger8r ../remoteattestation.edl --trusted --trusted-dir ../common
	$(CXX) -g -c $(CXXFLAGS) $(INCLUDES) ecalls.cpp ../common/attestation.cpp ../common/crypto.cpp ../common/dispatcher.cpp
	$(CC) -c $(CFLAGS) $(CINCLUDES) ../common/remoteattestation_t.c	
	$(CXX) -o enclave1.so attestation.o crypto.o ecalls.o dispatcher.o remoteattestation_t.o $(LDFLAGS)

sign:
	oesign enclave1.so enc.conf private.pem

clean:
	rm -f *.o *.so ../common/remoteattestation_t.* ../common/remoteattestation_args.h
