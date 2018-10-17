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
	oeedger8r ../datasealing.edl --trusted
	$(CC) -c $(CFLAGS) $(CINCLUDES) datasealing_t.c
	$(CXX) -c $(CXXFLAGS) $(INCLUDES) dispatcher.cpp keys.cpp
	$(CXX) -o ecalls_a_v1.o -c $(CXXFLAGS) $(INCLUDES) -DENCLAVE_NAME=\"Enclave1\" ecalls.cpp
	$(CXX) -o enclave_a_v1.so ecalls_a_v1.o dispatcher.o keys.o datasealing_t.o $(LDFLAGS)
	$(CXX) -o ecalls_a_v2.o -c $(CXXFLAGS) $(INCLUDES) -DENCLAVE_NAME=\"Enclave2\" ecalls.cpp
	$(CXX) -o enclave_a_v2.so ecalls_a_v2.o dispatcher.o keys.o datasealing_t.o $(LDFLAGS)
	$(CXX) -o ecalls_b.o -c $(CXXFLAGS) $(INCLUDES) -DENCLAVE_NAME=\"Enclave3\" ecalls.cpp
	$(CXX) -o enclave_b.so ecalls_b.o dispatcher.o keys.o datasealing_t.o $(LDFLAGS)

sign:
	oesign enclave_a_v1.so data-sealing.conf private_a.pem
	oesign enclave_a_v2.so data-sealing.conf private_a.pem
	oesign enclave_b.so data-sealing.conf private_b.pem

clean:
	rm -f *.so *.o *.pem datasealing_t.* datasealing_args.h

keys:
	openssl genrsa -out private_a.pem -3 3072
	openssl rsa -in private_a.pem -pubout -out public_a.pem
	openssl genrsa -out private_b.pem -3 3072
	openssl rsa -in private_b.pem -pubout -out public_b.pem
