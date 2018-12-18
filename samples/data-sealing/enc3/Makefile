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
	$(MAKE) keys
	$(MAKE) sign

build:
	@ echo "Compilers used: $(CC), $(CXX)"
	$(CXX) -c $(CXXFLAGS) $(INCLUDES) -std=c++11 ecalls.cpp ../common/dispatcher.cpp ../common/keys.cpp
	$(CC) -c $(CFLAGS) $(CINCLUDES) ../common/datasealing_t.c
	$(CXX) -o enclave_b.so ecalls.o dispatcher.o keys.o datasealing_t.o $(LDFLAGS)	

sign:
	oesign sign enclave_b.so data-sealing.conf private.pem

clean:
	rm -f *.so *.o *.pem 

keys:
	openssl genrsa -out private.pem -3 3072
	openssl rsa -in private.pem -pubout -out public.pem
