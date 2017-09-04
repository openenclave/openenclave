include $(OPENENCLAVE_DATADIR)/config.mak

CXXFLAGS = -Wall -Werror -O2 -m64 -nostdinc -fPIC -std=c++11 -nostdinc++

INCLUDES += -I$(OE_INCLUDEDIR)/openenclave/enclave
INCLUDES += -I$(OE_INCLUDEDIR)/openenclave/enclave/libcxx
INCLUDES += -I$(OE_INCLUDEDIR)/openenclave/enclave/libc

LDFLAGS += -Wl,--no-undefined 
LDFLAGS += -nostdlib 
LDFLAGS += -nodefaultlibs 
LDFLAGS += -nostartfiles 
LDFLAGS += -Wl,-Bstatic 
LDFLAGS += -Wl,-Bsymbolic 
LDFLAGS += -Wl,--export-dynamic 
LDFLAGS += -Wl,-pie,-eOE_Main 

LIBRARIES = -L${OE_LIBDIR}/openenclave/enclave -loelibcxx -loelibc -loeenclave

all: build sign

build:
	g++ -c $(CXXFLAGS) $(INCLUDES) enc.cpp -o enc.o
	g++ -o sortenc.so enc.o $(LDFLAGS) $(LIBRARIES)

sign:
	$(OE_BINDIR)/oesign sortenc.so sort.conf private.pem

clean:
	rm -f enc.o sortenc.so sortenc.signed.so

keys:
	openssl genrsa -out private.pem -3 3072
	openssl rsa -in private.pem -pubout -out public.pem
