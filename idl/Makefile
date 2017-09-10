.PHONY: archive 
.PHONY: gen

include ../mak/defs.mak

ARCHIVE = $(LIBDIR)/enclave/liboeidl.a

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
CFLAGS += -fno-builtin-__vfprintf_chk
CFLAGS += -fno-builtin-__memset_chk

INCLUDES += -I$(INCDIR) -I$(INCDIR)/openenclave/libc

DEFINES = -DOE_BUILD_ENCLAVE

SOURCES += $(wildcard *.c)

OBJECTS = $(SOURCES:.c=.o)

archive:
	$(MAKE) $(ARCHIVE)

$(ARCHIVE): $(OBJECTS)
	ar r $(ARCHIVE) $(OBJECTS)

%.o: %.c
	$(CC) -c $(DEFINES) $(CFLAGS) $(DEFINES) $(INCLUDES) -o $@ $<

clean:
	rm -f $(ARCHIVE) $(OBJECTS) .depends

include $(MAKDIR)/depend.mak
