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

CFLAGS=$(shell pkg-config oehost-$(C_COMPILER) --cflags)
CXXFLAGS=$(shell pkg-config oehost-$(CXX_COMPILER) --cflags)
LDFLAGS=$(shell pkg-config oehost-$(CXX_COMPILER) --libs)

all: build

build:
	@ echo "Compilers used: $(CC), $(CXX)"
	oeedger8r ../fileencryptor.edl --untrusted
	$(CXX) -g -c $(CXXFLAGS) host.cpp
	$(CC) -g -c $(CFLAGS) fileencryptor_u.c
	$(CXX) -o file-encryptorhost host.o fileencryptor_u.o $(LDFLAGS)

clean:
	rm -f file-encryptorhost fileencryptor_u.* fileencryptor_args.h *.o ../out.decrypted ../out.encrypted

