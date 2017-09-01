include $(OPENENCLAVE_DATADIR)/enclave.mak

all: build sign

CFLAGS = -g -O2 -Wall $(OE_CFLAGS)

INCLUDES = -I$(OE_INCLUDEDIR)/openenclave/enclave

LDFLAGS = $(OE_LDFLAGS)

build:
	gcc -c $(CFLAGS) $(INCLUDES) enc.c -o enc.o
	gcc -o helloenc.so enc.o $(LDFLAGS)

sign:
	$(OE_BINDIR)/oesign helloenc.so sign.conf private.pem 

clean:
	rm -f enc.o helloenc.so helloenc.signed.so

