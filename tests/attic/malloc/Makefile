include ../../mak/defs.mak

PROGRAM = ./testmalloc

INCLUDES += -I$(INCDIR)/host

SOURCES = main.c

LIBRARIES += $(LIBDIR)/host/liboehost.a

LDFLAGS += -L$(LIBDIR) -lcrypto

all:
	$(MAKE) program

CLEAN += log.txt log.bin log.hex

include $(TOP)/mak/program.mak

tests:
	$(PROGRAM)

gdb:
	gdb $(PROGRAM)

mc:
	$(MEMCHECK) ./testmalloc

CG_ANNOTATE_INCLUDES += --include=.
CG_ANNOTATE_INCLUDES += --include=$(INCDIR)
CG_ANNOTATE_INCLUDES += --include=$(TOP)/encu
CG_ANNOTATE_INCLUDES += --include=$(TOP)/common

cg:
	$(CACHEGRIND) $(PROGRAM)
	$(CG_ANNOTATE) cachegrind.out > cg_annotate.out
	@ rm cachegrind.out
	@ echo "Created cg_annotate.out"

