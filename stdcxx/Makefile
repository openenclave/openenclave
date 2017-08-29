.PHONY: archive 
.PHONY: gen

include ../mak/defs.mak

ARCHIVE = $(LIBDIR)/libecxxrt.a

CC = gcc
CXX = g++

CFLAGS += -Wall
CFLAGS += -Werror
CFLAGS += -g
CFLAGS += -O2
CFLAGS += -m64
CFLAGS += -nostdinc
CFLAGS += -Wno-attributes
CFLAGS += -fPIC
CFLAGS += -fno-stack-protector
CFLAGS += -fvisibility=hidden
CFLAGS += -Wmissing-prototypes
CFLAGS += -Wstrict-prototypes
CFLAGS += -fno-builtin-memcpy
CFLAGS += -fno-builtin-memset

INCLUDES += -I$(TOP)/include 
INCLUDES += -I$(TOP)/include/musl

DEFINES += -DOE_BUILD_ENCLAVE

SOURCES +=

OBJECTS = $(SOURCES:.cpp=.o)

COPTS = $(DEFINES) $(CFLAGS) $(DEFINES) $(INCLUDES)

archive: $(ARCHIVE)

$(ARCHIVE): $(OBJECTS)
	mkdir -p $(LIBDIR)
	ar r $(ARCHIVE) $(OBJECTS)

%.o: %.cpp
	$(CXX) -c $(COPTS) -o $@ $<

clean:
	rm -f $(ARCHIVE) $(OBJECTS) .depends

include $(MAKDIR)/depend.mak
-include .depends
