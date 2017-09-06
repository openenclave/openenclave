include $(OPENENCLAVE_CONFIG)

all: build

CFLAGS=-Wall -O2

INCLUDES=-I$(OE_INCLUDEDIR)

LDFLAGS += -rdynamic 
LDFLAGS += -loehost

LIBRARIES += -L$(OE_LIBDIR)/openenclave/host 
LIBRARIES += -lcrypto 
LIBRARIES += -lpthread 
LIBRARIES += -ldl

build:
	gcc -c $(CFLAGS) $(INCLUDES) host.c
	gcc -o hellohost host.o $(LDFLAGS) $(LIBRARIES)

clean:
	rm -f hellohost host.o 
