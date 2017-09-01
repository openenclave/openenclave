include $(OPENENCLAVE_DATADIR)/host.mak

all: build

CXXFLAGS=-Wall -O2

INCLUDES=-I$(OE_INCLUDEDIR)/openenclave/host

LDFLAGS=-rdynamic -L$(OE_LIBDIR)/openenclave/host -loehost -lcrypto -lpthread -ldl

build:
	g++ -c $(CXXFLAGS) $(INCLUDES) host.cpp
	g++ -o sorthost host.o $(LDFLAGS)

clean:
	rm -f sorthost host.o 

