include $(OPENENCLAVE_CONFIG)

CFLAGS = -Wall -Werror -O2 -m64 -nostdinc -fPIC

INCLUDES = -I$(OE_INCLUDEDIR)

LDFLAGS += -Wl,--no-undefined 
LDFLAGS += -nostdlib 
LDFLAGS += -nodefaultlibs 
LDFLAGS += -nostartfiles 
LDFLAGS += -Wl,-Bstatic 
LDFLAGS += -Wl,-Bsymbolic 
LDFLAGS += -Wl,--export-dynamic 
LDFLAGS += -Wl,-pie
LDFLAGS += -Wl,-eOE_Main 

LIBRARIES = -L${OE_LIBDIR}/openenclave/enclave -loeenclave

all: 
	$(MAKE) build 
	$(MAKE) sign

build:
	gcc -c $(CFLAGS) $(INCLUDES) enc.c -o enc.o
	gcc -o echoenc.so enc.o $(LDFLAGS) $(LIBRARIES)

sign:
	$(OE_BINDIR)/oesign echoenc.so echo.conf private.pem

clean:
	rm -f enc.o echoenc.so echoenc.signed.so

keys:
	openssl genrsa -out private.pem -3 3072
	openssl rsa -in private.pem -pubout -out public.pem
