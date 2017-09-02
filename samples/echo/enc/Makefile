include $(OPENENCLAVE_DATADIR)/enclave.mak

all: build sign

CFLAGS = -O2 -Wall $(OE_CFLAGS)

INCLUDES = -I$(OE_INCLUDEDIR)/openenclave/enclave

LDFLAGS = $(OE_LDFLAGS)

build:
	gcc -c $(CFLAGS) $(INCLUDES) enc.c -o enc.o
	gcc -o echoenc.so enc.o $(LDFLAGS)

sign:
	$(OE_BINDIR)/oesign echoenc.so echo.conf private.pem

clean:
	rm -f enc.o echoenc.so echoenc.signed.so

keys:
	openssl genrsa -out private.pem -3 3072
	openssl rsa -in private.pem -pubout -out public.pem
