include $(OPENENCLAVE_CONFIG)

all: build

CFLAGS=-Wall -O2

INCLUDES=-I$(OE_INCLUDEDIR)

LDFLAGS=-rdynamic -L$(OE_LIBDIR)/openenclave/host -loehost -lcrypto -lpthread -ldl

build:
	gcc -c $(CFLAGS) $(INCLUDES) host.c
	gcc -o echohost host.o $(LDFLAGS)

clean:
	rm -f echohost host.o 
