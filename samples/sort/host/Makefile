include $(OPENENCLAVE_DATADIR)/config.mak

all: build

CXXFLAGS=-Wall -O2

INCLUDES = -I$(OE_INCLUDEDIR)/openenclave/host

LDFLAGS += -rdynamic 

LIBRARIES += -L$(OE_LIBDIR)/openenclave/host 
LIBRARIES += -loehost 
LIBRARIES += -lcrypto 
LIBRARIES += -lpthread 
LIBRARIES += -ldl

build:
	g++ -c $(CXXFLAGS) $(INCLUDES) host.cpp
	g++ -o sorthost host.o $(LDFLAGS) $(LIBRARIES)

clean:
	rm -f sorthost host.o 

