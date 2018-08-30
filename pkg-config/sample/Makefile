ENCLAVE_CFLAGS=$(shell pkg-config oeenclave --cflags)
ENCLAVE_LIBS=$(shell pkg-config oeenclave --libs)

HOST_CFLAGS=$(shell pkg-config oehost --cflags)
HOST_LIBS=$(shell pkg-config oehost --libs)

all: build_enclave build_host

build_enclave:
	gcc $(ENCLAVE_CFLAGS) -o enc enc.c $(ENCLAVE_LIBS)


build_host:
	gcc $(HOST_CFLAGS) -o host host.c $(HOST_LIBS)

run:
	./host enc

clean:
	rm -rf enc host
