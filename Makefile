SHELL=/bin/bash
include mak/defs.mak
-include config.mak

.PHONY: tests
.PHONY: prereqs
.PHONY: samples

##==============================================================================
##
## Check whether ./configure was run (creates ./config)
##
##==============================================================================

ifndef OE_CONFIGURED
$(error Please run ./configure first)
endif

##==============================================================================
##
## build:
##
##==============================================================================

DIRS = tools/oesgx 3rdparty enclave libc libcxx host idl tools tests

build:
	$(foreach i, $(DIRS), $(MAKE) -C $(i) $(NEWLINE) )

##==============================================================================
##
## depend:
##
##==============================================================================

depend:
	$(foreach i, $(DIRS), $(MAKE) -C $(i) depend $(NEWLINE) )

##==============================================================================
##
## clean:
##
##==============================================================================

clean:
	$(foreach i, $(DIRS), $(MAKE) -C $(i) clean $(NEWLINE) )
	rm -rf bin
	rm -rf lib
	rm -rf obj

##==============================================================================
##
## distclean:
##
##==============================================================================

DISTNAME=openenclave-$(OE_VERSION)

distclean: clean
	rm -rf include/musl
	rm -rf include/stlport
	$(MAKE) -s -C prereqs distclean 2> /dev/null
	$(MAKE) -C 3rdparty distclean
	rm -rf lib bin tmp
	rm -f include/enclave/oecommon
	rm -f include/enclave/oeinternal
	rm -f include/host/oecommon
	rm -f include/host/oeinternal
	rm -f $(DISTNAME).tar.gz
	rm -rf $(DISTNAME)
	rm -f config.mak
	rm -rf scripts/ccache

##==============================================================================
##
## tests:
##
##==============================================================================

tests:
	$(MAKE) -s -C tests tests

##==============================================================================
##
## world:
##
##==============================================================================

world:
	$(MAKE) -s clean
	$(MAKE)
	$(MAKE) -s -C tests tests
	$(MAKE) samples

##==============================================================================
##
## sub:
##
##==============================================================================

SUB = $(shell find . -name '*.[ch]') $(shell find . -name '*.cpp')

sub:
	./scripts/sub $(SUB)

##==============================================================================
##
## dist:
##
##==============================================================================

dist:
	@ $(MAKE) -s -f mak/dist.mak DISTNAME=$(DISTNAME) TOP=$(TOP)

##==============================================================================
##
## big:
##
##==============================================================================

big:
	find . -size +1000

##==============================================================================
##
## prereqs:
##
##==============================================================================

prereqs:
	$(MAKE) -C prereqs
	$(MAKE) -C prereqs install

##==============================================================================
##
## install:
##
##==============================================================================

install:
	@ ./scripts/install

remove-test-install:
	@ $(MAKE) test-install

test-install:
	( cd $(OE_DATADIR)/openenclave/samples; ./run )

##==============================================================================
##
## check:
##
##==============================================================================

CHECKDIR=$(TMPDIR)/$(DISTNAME)

check:
	$(MAKE) -s -f mak/check.mak DISTNAME=$(DISTNAME)

##==============================================================================
##
## samples:
##
##==============================================================================

export OPENENCLAVE_CONFIG=$(TMPDIR)/samples-config.mak

samples-config:
	@ rm -f $(OPENENCLAVE_CONFIG)
	@ rm -rf $(TMPDIR)/lib
	@ mkdir -p $(TMPDIR)/lib
	@ cp -r $(LIBDIR) $(TMPDIR)/lib/openenclave
	@ echo "OE_CONFIGURED=$(OE_CONFIGURED)" >> $(OPENENCLAVE_CONFIG)
	@ echo "OE_DISTRONAME=$(OE_DISTRONAME)" >> $(OPENENCLAVE_CONFIG)
	@ echo "OE_MAJOR=$(OE_MAJOR)" >> $(OPENENCLAVE_CONFIG)
	@ echo "OE_MINOR=$(OE_MINOR)" >> $(OPENENCLAVE_CONFIG)
	@ echo "OE_REVISION=$(OE_REVISION)" >> $(OPENENCLAVE_CONFIG)
	@ echo "OE_PREFIX=$(TOP)" >> $(OPENENCLAVE_CONFIG)
	@ echo "OE_LIBDIR=$(TMPDIR)/lib" >> $(OPENENCLAVE_CONFIG)
	@ echo "OE_BINDIR=$(BINDIR)" >> $(OPENENCLAVE_CONFIG)
	@ echo "OE_INCLUDEDIR=$(INCDIR)" >> $(OPENENCLAVE_CONFIG)

samples: samples-config
	$(MAKE) -s -C samples world

##==============================================================================
##
## refman:
##
##     Generate all Doxygen documentation format from OpenEnclave sources.
##
##==============================================================================

refman:
	$(MAKE) -C doc/refman

##==============================================================================
##
## cloc:
##
##     Count lines of orignal code:
##
##==============================================================================

CLOC += $(wildcard enclave/*.c)
CLOC += $(wildcard host/*.c)
CLOC += $(wildcard include/enclave/openenclave.h)
CLOC += $(wildcard include/host/openenclave.h)
CLOC += $(wildcard include/oecommon/*.h)
CLOC += $(wildcard include/oeinternal/*.h)
CLOC += $(wildcard libc/*.c)
CLOC += $(wildcard common/*.c)

cloc:
	cloc $(CLOC)
