include ../mak/defs.mak

DIRS = dlmalloc musl libcxxrt libunwind libcxx mbedtls

include $(MAKDIR)/dirs.mak

CLOC += $(shell find . -name '*.cpp')
CLOC += $(shell find . -name '*.h')
CLOC += $(shell find . -name '*.cc')
CLOC += $(shell find . -name '*.c')
CLOC += $(shell find . -name '*.h')
CLOC += $(shell find . -name '*.hpp')
CLOC += $(wildcard libcxx/trunk/include/*)

cloc:
	cloc $(CLOC)
