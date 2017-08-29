.PHONY: archive 

include ../mak/defs.mak
#include $(MAKDIR)/sgx.mak

ARCHIVE = $(LIBDIR)/host/libhost.a

CC = gcc

CXX = g++

CFLAGS = -g -Wall -Werror -m64 -O2 -fPIC -Wno-attributes -fPIC -g -Wmissing-prototypes

CXXFLAGS = $(CFLAGS) -std=c++11

DEFINES += -DOE_BUILD_UNTRUSTED

INCLUDES += -I$(HOSTINCDIR)

SOURCES += $(wildcard *.c)

OBJECTS = $(SOURCES:.c=.o)

OBJECTS += enter.o entersim.o

archive:
	$(MAKE) $(ARCHIVE)

$(ARCHIVE): $(OBJECTS)
	mkdir -p $(LIBDIR)
	ar r $(ARCHIVE) $(OBJECTS)

%.o: %.c
	$(CC) -c $(CFLAGS) $(DEFINES) $(INCLUDES) -o $@ $<

enter.o: enter.S
	$(CC) -c $(CFLAGS) $(DEFINES) $(INCLUDES) -o enter.o enter.S

entersim.o: entersim.S
	$(CC) -c $(CFLAGS) $(DEFINES) $(INCLUDES) -o entersim.o entersim.S

clean:
	rm -f $(ARCHIVE) $(OBJECTS) api_u.c api_u.h .depends

malloc.o: ../common/malloc.c

SEARCHPATH=--search-path .. --search-path /opt/intel/sgxsdk/include

include $(MAKDIR)/depend.mak
-include .depends

asm:
	$(CC) -c $(CFLAGS) $(DEFINES) $(INCLUDES) -S calls.c
