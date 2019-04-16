# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

# Detect C and C++ compiler options
# if not gcc and g++, default to clang-8
C_COMPILER=$(notdir $(CC))
ifeq ($(C_COMPILER), gcc)
        CXX_COMPILER=$(notdir $(CXX))
        USE_GCC = true
endif

ifeq ($(USE_GCC),)
        CC = clang-8
        CXX = clang++-8
        C_COMPILER=clang
        CXX_COMPILER=clang++
endif

CFLAGS=$(shell pkg-config oehost-$(C_COMPILER) --cflags)
CXXFLAGS=$(shell pkg-config oehost-$(CXX_COMPILER) --cflags)
LDFLAGS=$(shell pkg-config oehost-$(CXX_COMPILER) --libs)

all: build

build:
	@ echo "Compilers used: $(CC), $(CXX)"
	oeedger8r ../remoteattestation.edl --untrusted
	$(CC) -g -c $(CFLAGS) $(CINCLUDES) remoteattestation_u.c
	$(CXX) -g -c $(CXXFLAGS) $(INCLUDES) host.cpp
	$(CXX) -o attestation_host host.o remoteattestation_u.o $(LDFLAGS)

clean:
	rm -f attestation_host *.o remoteattestation_u.*  remoteattestation_args.h



