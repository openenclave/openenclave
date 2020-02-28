# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.

ifndef OpenEnclave_DIR
$(error "Please source the 'openenclaverc' file")
endif

HOST_CFLAGS=$(shell pkg-config --cflags oehost-gcc)
HOST_LIBS=$(shell pkg-config --libs oehost-gcc)

ENCLAVE_CFLAGS=$(shell pkg-config --cflags oeenclave-gcc)

ENCLAVE_LIBS += $(shell pkg-config --libs oeenclave-gcc)
ENCLAVE_LIBS += -lmbedtls
ENCLAVE_LIBS += -loehostsock
ENCLAVE_LIBS += -loehostresolver

all: host enclave

host:
	oeedger8r --untrusted tlssrv.edl
	$(CC) -c $(HOST_CFLAGS) main.c
	$(CC) -c $(HOST_CFLAGS) tlssrv_u.c
	$(CC) -o tlssrv $(HOST_CFLAGS) main.o tlssrv_u.o $(HOST_LIBS)

enclave:
	oeedger8r --trusted tlssrv.edl
	$(CC) -c $(ENCLAVE_CFLAGS) srv.c
	$(CC) -c $(ENCLAVE_CFLAGS) tlssrv.c
	$(CC) -c $(ENCLAVE_CFLAGS) tlssrv_t.c
	$(CC) -c $(ENCLAVE_CFLAGS) ../common/gencreds.c
	$(CC) -o tlssrv_enclave $(ENCLAVE_CFLAGS) srv.o tlssrv.o tlssrv_t.o gencreds.o -lmbedtls $(ENCLAVE_LIBS)

CLEAN += *.o
CLEAN += tlssrv tlssrv_enclave
CLEAN += tlssrv_t.c tlssrv_u.c tlssrv_t.h tlssrv_u.h tlssrv_args.h

clean:
	rm -f $(CLEAN)
