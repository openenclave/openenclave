include $(OPENENCLAVE_DATADIR)/host.mak

all: build

CFLAGS=-Wall -O2

INCLUDES=-I$(OE_INCLUDEDIR)/openenclave/host

LDFLAGS=-rdynamic -L$(OE_LIBDIR)/openenclave/host -lhost -lcrypto -lpthread -ldl

build:
	gcc -c $(CFLAGS) $(INCLUDES) host.c
	gcc -o hellohost host.o $(LDFLAGS)

clean:
	rm -f hellohost host.o 
