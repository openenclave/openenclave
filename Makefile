include mak/defs.mak
.PHONY: tests
.PHONY: prereqs

DIRS = 3rdparty gen host elibc enclave ecrypto elf sign tests

define NL


endef

build:
	$(foreach i, $(DIRS), $(MAKE) -C $(i) $(NL) )

depend:
	$(foreach i, $(DIRS), $(MAKE) -C $(i) depend $(NL) )

tests:
	$(MAKE) -s -C tests tests

SOURCES = $(shell find . -name '*.[ch]') $(shell find . -name '*.cpp')

sub:
	sub $(SOURCES)

world:
	$(MAKE) -s clean
	$(MAKE)
	$(MAKE) -s -C tests tests

##==============================================================================
##
## dist:
##
##==============================================================================

DISTNAME=openenclave-$(shell cat VERSION)

dist:
	@ rm -rf /tmp/$(DISTNAME)
	@ ( cd ..; cp -r OpenEnclave /tmp/$(DISTNAME) )
	@ $(MAKE) -C /tmp/$(DISTNAME) -s distclean
	@ ( cd /tmp; tar zcf $(TOP)/$(DISTNAME).tar.gz $(DISTNAME) )
	@ echo "Created $(TOP)/$(DISTNAME).tar.gz"

##==============================================================================
##
## clean:
##
##==============================================================================

clean:
	$(foreach i, $(DIRS), $(MAKE) -C $(i) clean $(NL) )
	rm -rf bin
	rm -rf lib
	rm -rf obj

##==============================================================================
##
## distclean:
##
##==============================================================================

distclean: clean
	rm -rf include/musl
	rm -rf include/stlport
	$(MAKE) -s -C prereqs distclean 2> /dev/null
	$(MAKE) -C 3rdparty distclean
	rm -rf lib
	rm -f include/enclave/oecommon
	rm -f include/enclave/oeinternal
	rm -f include/host/oecommon
	rm -f include/host/oeinternal
	rm -f $(DISTNAME).tar.gz
	rm -f $(DISTNAME)

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
