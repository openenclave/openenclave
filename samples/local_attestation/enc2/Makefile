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
	@ echo "Compilers used: $(CC), $(CXX)"
	oeedger8r ../localattestation.edl --trusted --trusted-dir ../common
	$(CXX) -g -c $(CXXFLAGS) $(INCLUDES) ecalls.cpp ../common/attestation.cpp ../common/crypto.cpp ../common/dispatcher.cpp
	$(CC) -c $(CFLAGS) $(CINCLUDES) ../common/localattestation_t.c	
	$(CXX) -o enclave2.so attestation.o crypto.o ecalls.o dispatcher.o localattestation_t.o $(LDFLAGS)

sign:
	oesign enclave2.so enc.conf private.pem

clean:
	rm -f *.o *.so ../common/localattestation_t.* ../common/remoteattestation_args.h
