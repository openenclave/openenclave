# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.

ifndef OpenEnclave_DIR
$(error "Please source the 'openenclaverc' file")
endif

HOST_CFLAGS=$(shell pkg-config --cflags oehost-gcc)
HOST_LIBS=$(shell pkg-config --libs oehost-gcc)

ENCLAVE_CFLAGS=$(shell pkg-config --cflags oeenclave-gcc)
ENCLAVE_LIBS=$(shell pkg-config --libs oeenclave-gcc)

all: host enclave

host:
	oeedger8r --untrusted gencreds.edl
	$(CC) -c $(HOST_CFLAGS) main.c
	$(CC) -c $(HOST_CFLAGS) gencreds_u.c
	$(CC) -o gencreds $(HOST_CFLAGS) main.o gencreds_u.o $(HOST_LIBS)

enclave:
	oeedger8r --trusted gencreds.edl
	$(CC) -c $(ENCLAVE_CFLAGS) enclave.c
	$(CC) -c $(ENCLAVE_CFLAGS) gencreds_t.c
	$(CC) -c $(ENCLAVE_CFLAGS) ../common/gencreds.c
	$(CC) -o gencreds_enclave $(ENCLAVE_CFLAGS) enclave.o gencreds_t.o gencreds.o $(ENCLAVE_LIBS)

CLEAN += *.o
CLEAN += gencreds gencreds_enclave
CLEAN += gencreds_t.c gencreds_u.c gencreds_t.h  gencreds_u.h gencreds_args.h

clean:
	rm -f $(CLEAN)
