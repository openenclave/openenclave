.PHONY: tests.all tests wraptests

include ../../mak/defs.mak

##==============================================================================
##
## build:
##
##     Build all enclaves that reside in subdirectories. All subdirectories
##     that failed to build will contain the 'fail.build' file.
##
##==============================================================================

DIRS += $(wildcard *.wraptest)

build:
	$(MAKE) wraptests
	$(MAKE) build-enclaves

build-enclaves:
	$(foreach i, $(DIRS), - $(MAKE) build-enclave DIR=$(i) $(NEWLINE) )

build-enclave:
	$(MAKE) -C $(DIR) 2>&1 | tee $(DIR)/build.log
	@ stat $(DIR)/libcxxenc.signed.so 2> /dev/null > /dev/null
	rm -f $(DIR)/build.log

##==============================================================================
##
## clean:
##
##     The clean target for the enclave subdirectories.
##
##==============================================================================

clean:
	$(foreach i, $(DIRS), $(MAKE) -C $(i) clean $(NEWLINE) )

##==============================================================================
##
## distclean:
##
##     Remove all auto-generated enclave directories.
##
##==============================================================================

distclean:
	rm -rf $(DIRS) tmp[1-9] .wraptests

##==============================================================================
##
## depend:
##
##     Empty depend target.
##
##==============================================================================

depend:

##==============================================================================
##
## tests:
##
##     Run all tests that successfully built a shared object.
##
##==============================================================================

ENCLAVES = $(wildcard *.wraptest/libcxxenc.signed.so)

RUNTEST=$(TOP)/tests/runtest/runtest

tests:
	$(foreach i, $(ENCLAVES), - $(MAKE) test TEST=$(i) $(NEWLINE) )

DIR=$(shell dirname $(TEST))

test:
	$(RUNTEST) $(TEST) 2>&1 | tee $(DIR)/test.log
	@ grep -q "=== passed:" $(DIR)/test.log 
	@ rm -f $(DIR)/test.log

##==============================================================================
##
## tests.all:
##
##     Generate tests.all by scanning the libcxx test directory for tests that
##     meet the following criteria.
##
##         (1) Supports C++14
##         (2) Supports GCC
##         (3) Are 'pass' rather than 'fail' tests (which fail compilation).
##
##==============================================================================

tests.all:
	@ ( find $(TOP)/3rdparty/libcxx/libcxx/test -name '*.cpp' > tmp1 )
	@ grep -L "UNSUPPORTED:.*c++14" `cat tmp1` > tmp2
	@ grep -L "XFAIL:.*gcc" `cat tmp2` > tmp3
	@ grep -l "int.*\<main\>" `cat tmp3` > tmp4
	@ grep -v "\.fail\." tmp4 > tests.all
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
