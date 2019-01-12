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
	oeedger8r ../fileencryptor.edl --trusted
	$(CXX) -g -c $(CXXFLAGS) -std=c++11 ecalls.cpp encryptor.cpp keys.cpp
	$(CC) -g -c $(CFLAGS) fileencryptor_t.c -o fileencryptor_t.o
	$(CXX) -o file-encryptorenc ecalls.o encryptor.o keys.o fileencryptor_t.o $(LDFLAGS)

sign:
	oesign sign file-encryptorenc file-encryptor.conf private.pem

clean:
	rm -f file-encryptorenc file-encryptorenc.signed *.o fileencryptor_t.* fileencryptor_args.h private.pem public.pem

keys:
	openssl genrsa -out private.pem -3 3072
	openssl rsa -in private.pem -pubout -out public.pem


