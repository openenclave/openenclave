include mak/defs.mak
-include .config

.PHONY: tests
.PHONY: prereqs

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

DIRS = 3rdparty gen host crypto libc enclave elf sign tests

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
	rm -rf lib bin
	rm -f include/enclave/oecommon
	rm -f include/enclave/oeinternal
	rm -f include/host/oecommon
	rm -f include/host/oeinternal
	rm -f $(DISTNAME).tar.gz
	rm -f $(DISTNAME)
	rm -f .config

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
	@ rm -rf /tmp/$(DISTNAME)
	@ ( cd ..; cp -r openenclave /tmp/$(DISTNAME) )
	@ $(MAKE) -C /tmp/$(DISTNAME) -s distclean
	@ ( cd /tmp; tar zcf $(TOP)/$(DISTNAME).tar.gz $(DISTNAME) )
	@ echo "Created $(TOP)/$(DISTNAME).tar.gz"

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

##==============================================================================
##
## check:
##
##==============================================================================

CHECKDIR=$(CURDIR)/.check

check:
	rm -rf $(CHECKDIR)
	@ $(MAKE) distclean
	@ ./configure --prefix=$(CHECKDIR)
	@ $(MAKE)
	@ $(MAKE) tests
	@ $(MAKE) install
	( source $(CHECKDIR)/share/openenclave/environment; \
          cd $(CHECKDIR)/share/openenclave/samples; \
          $(MAKE); \
          $(MAKE) run )
	rm -rf $(CHECKDIR)
	@ echo
	@ echo "Check okay!"

