# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

OPENENCLAVE_CONFIG=../../config.mak
include $(OPENENCLAVE_CONFIG)

CXXFLAGS = -Wall -Werror -O2 -m64 -nostdinc -fPIC -std=c++11 -nostdinc++

INCLUDES += -I$(OE_INCLUDEDIR)
INCLUDES += -I$(OE_INCLUDEDIR)/libcxx
INCLUDES += -I$(OE_INCLUDEDIR)/libc

LDFLAGS += -Wl,--no-undefined 
LDFLAGS += -nostdlib 
LDFLAGS += -nodefaultlibs 
LDFLAGS += -nostartfiles 
LDFLAGS += -Wl,-Bstatic 
LDFLAGS += -Wl,-Bsymbolic 
LDFLAGS += -Wl,--export-dynamic 
LDFLAGS += -Wl,-pie
LDFLAGS += -Wl,-eoe_main 

LIBRARIES += -L${OE_LIBDIR}/openenclave/enclave 
LIBRARIES += -loelibcxx 
LIBRARIES += -loelibc 
LIBRARIES += -loeenclave 
LIBRARIES += -loembedtls

all:
	$(MAKE) build
	$(MAKE) sign

build:
	g++ -c $(CXXFLAGS) $(INCLUDES) enc.cpp -o enc.o
	g++ -o sortenc.so enc.o $(LDFLAGS) $(LIBRARIES)

sign:
	$(OE_BINDIR)/oesign sortenc.so sort.conf private.pem

clean:
	rm -f enc.o sortenc.so sortenc.signed.so

keys:
	openssl genrsa -out private.pem -3 3072
	openssl rsa -in private.pem -pubout -out public.pem
