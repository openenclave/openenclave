# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.

include ../../config.mk

CFLAGS=$(shell pkg-config oehost-$(C_COMPILER) --cflags)
CXXFLAGS=$(shell pkg-config oehost-$(CXX_COMPILER) --cflags)
LDFLAGS=$(shell pkg-config oehost-$(C_COMPILER) --libs)


all: build

build:
	@ echo "Compilers used: $(CC), $(CXX)"
	oeedger8r ../datasealing.edl --untrusted
	$(CXX) -g -c $(CXXFLAGS) $(INCLUDES) -I.. host.cpp
	$(CC) -g -c $(CFLAGS) $(CINCLUDES) -I.. datasealing_u.c
	$(CXX) -o data-sealing_host host.o datasealing_u.o $(LDFLAGS)

clean:
	rm -f data-sealing_host *.o datasealing_u.* datasealing_args.h
