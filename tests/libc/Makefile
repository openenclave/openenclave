include ../../mak/defs.mak

DIRS += $(wildcard *.wraptest)

build:
	$(MAKE) wraptests
	$(MAKE) build-enclaves

build-enclaves:
	$(foreach i, $(DIRS), $(MAKE) -C $(i) $(NEWLINE) )

RUNTEST=$(TOP)/tests/runtest/runtest

tests:
	@ $(foreach i, $(DIRS), $(RUNTEST) $(i)/libcenc.signed.so $(NEWLINE) )

clean:
	$(foreach i, $(DIRS), $(MAKE) -C $(i) clean $(NEWLINE) )

distclean:
	rm -rf *.wraptest .wraptests

depend:

##==============================================================================
##
## tests.all:
##
##     Generate tests.all by scanning the libc-test directory for tests that
##     have a main() function.
##
##==============================================================================

tests.all:
	@ ( find $(TOP)/3rdparty/musl/libc-test -name '*.c' > tmp1 )
	@ grep -l "int.*\<main\>" `cat tmp1` > tests.all
	@ rm -f tmp[1-9]

##==============================================================================
##
## wraptests:
##
##     Wrap all test in an enclave, generating a directory for each.
##
##==============================================================================

wraptests: .wraptests

.wraptests:
	./wraptests
	touch .wraptests

##==============================================================================
##
## world:
##
##     Regenerate, build, and run all tests.
##
##==============================================================================

world:
	$(MAKE) -C template clean
	$(MAKE) distclean
	$(MAKE) build
	$(MAKE) tests
