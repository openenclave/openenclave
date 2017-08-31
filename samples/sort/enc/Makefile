include $(OPENENCLAVE_DATADIR)/enclave.mak

all: build sign

CXXFLAGS = -g -O2 $(OE_CFLAGS)

INCLUDES = -I$(OE_INCLUDEDIR)/openenclave/enclave/cxx -I$(OE_INCLUDEDIR)/openenclave/enclave 

LDFLAGS = $(OE_CXXLDFLAGS)

build:
	g++ -c $(CXXFLAGS) $(INCLUDES) enc.cpp -o enc.o
	g++ -o sortenc.so enc.o $(LDFLAGS)

sign:
	$(OE_BINDIR)/openenclave/oesign sortenc.so sign.conf private.pem 

clean:
	rm -f enc.o sortenc.so sortenc.signed.so

