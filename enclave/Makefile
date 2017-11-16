.PHONY: archive 
.PHONY: gen

include ../mak/defs.mak

ARCHIVE = $(LIBDIR)/enclave/liboeenclave.a

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

INCLUDES += -I$(INCDIR)

DEFINES = -DOE_BUILD_ENCLAVE

SOURCES += $(wildcard *.c)

OBJECTS = $(SOURCES:.c=.o)
OBJECTS += main.o
OBJECTS += exit.o
OBJECTS += abort.o

archive:
	$(MAKE) $(ARCHIVE)

$(ARCHIVE): $(OBJECTS)
	ar r $(ARCHIVE) $(OBJECTS)

%.o: %.c
	$(CC) -c $(DEFINES) $(CFLAGS) $(DEFINES) $(INCLUDES) -o $@ $<

enter.o: main.S
	$(CC) -c $(CFLAGS) $(DEFINES) $(INCLUDES) -o enter.o main.S

exit.o: exit.S
	$(CC) -c $(CFLAGS) $(DEFINES) $(INCLUDES) -o exit.o exit.S

abort.o: abort.S
	$(CC) -c $(CFLAGS) $(DEFINES) $(INCLUDES) -o abort.o abort.S

search.o: search.c
	$(CC) -c $(CFLAGS) $(DEFINES) -Iinclude $(INCLUDES) -o search.o search.c

heap.o: ../common/heap.c

clean:
	rm -f $(ARCHIVE) $(OBJECTS) .depends

include $(MAKDIR)/depend.mak

asm:
	$(CC) -c $(CFLAGS) $(DEFINES) $(INCLUDES) -S report.c

