# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

OPENENCLAVE_CONFIG=../../config.mak
include $(OPENENCLAVE_CONFIG)

# C++ build environment setup
CXX = clang++-7
CXXFLAGS += -Wall -Werror -g -m64 -nostdinc -fPIC -std=c++11 -nostdinc++
CXXFLAGS += -mllvm -x86-speculative-load-hardening
INCLUDES += -I$(OE_INCLUDEDIR)
INCLUDES += -I$(OE_INCLUDEDIR)/libcxx
INCLUDES += -I$(OE_INCLUDEDIR)/libc

# C build environment setup
CC = clang-7
CFLAGS += -Wall -Werror -O2 -m64 -nostdinc -fPIC
CFLAGS += -mllvm -x86-speculative-load-hardening
CINCLUDES += -I$(OE_INCLUDEDIR)
CINCLUDES += -I$(OE_INCLUDEDIR)/libc

LDFLAGS += -Wl,--no-undefined 
LDFLAGS += -nostdlib 
LDFLAGS += -nodefaultlibs 
LDFLAGS += -nostartfiles 
LDFLAGS += -Wl,-Bstatic 
LDFLAGS += -Wl,-Bsymbolic 
LDFLAGS += -Wl,--export-dynamic 
LDFLAGS += -Wl,-pie

LIBRARIES += -L${OE_LIBDIR}/openenclave/enclave 
LIBRARIES += -loeenclave
LIBRARIES += -loelibcxx
LIBRARIES += -lmbedx509 
LIBRARIES += -lmbedcrypto 
LIBRARIES += -loelibc
LIBRARIES += -loecore


all:
	$(MAKE) build
	$(MAKE) keys
	$(MAKE) sign

build:
	$(CXX) -c $(CXXFLAGS) $(INCLUDES) ecalls.cpp ../common/dispatcher.cpp ../common/keys.cpp
	$(CC) -c $(CFLAGS) $(CINCLUDES) ../common/datasealing_t.c
	$(CXX) -o enclave_b.so ecalls.o dispatcher.o keys.o datasealing_t.o $(LDFLAGS) $(LIBRARIES)	

sign:
	$(OE_BINDIR)/oesign enclave_b.so data-sealing.conf private.pem

clean:
	rm -f *.so *.o *.pem 

keys:
	openssl genrsa -out private.pem -3 3072
	openssl rsa -in private.pem -pubout -out public.pem
