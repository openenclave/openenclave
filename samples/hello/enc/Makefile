include $(OPENENCLAVE_DATADIR)/config.mak

CFLAGS = -Wall -Werror -O2 -m64 -nostdinc -fPIC

INCLUDES += -I$(OE_INCLUDEDIR)/openenclave/enclave/libc
INCLUDES += -I$(OE_INCLUDEDIR)/openenclave/enclave

LDFLAGS += -Wl,--no-undefined 
LDFLAGS += -nostdlib 
LDFLAGS += -nodefaultlibs 
LDFLAGS += -nostartfiles 
LDFLAGS += -Wl,-Bstatic 
LDFLAGS += -Wl,-Bsymbolic 
LDFLAGS += -Wl,--export-dynamic 
LDFLAGS += -Wl,-pie,-eOE_Main 

LIBRARIES = -L${OE_LIBDIR}/openenclave/enclave -loeenclave

all: build sign

build:
	gcc -c $(CFLAGS) $(INCLUDES) enc.c -o enc.o
	gcc -o helloenc.so enc.o $(LDFLAGS) $(LIBRARIES)

sign:
	$(OE_BINDIR)/oesign helloenc.so hello.conf private.pem

clean:
	rm -f enc.o helloenc.so helloenc.signed.so

keys:
	openssl genrsa -out private.pem -3 3072
	openssl rsa -in private.pem -pubout -out public.pem
