include ../../mak/defs.mak

PROGRAM = runtest

SOURCES = runtest.cpp

include $(TOP)/mak/host.mak

export OE_TOP=$(TOP)

CLEAN = $(wildcard *.test)

WRAPTEST = $(TOP)/tests/wraptest/wraptest

TESTDIR = $(wildcard *.wraptest)

tests:
	@ $(MAKE) -s wrap-test
	@ $(MAKE) -s build-test
	@ $(MAKE) -s run-test

wrap-test:
	@ rm -rf *.wraptest
	@ $(WRAPTEST) template test.c

build-test:
	$(MAKE) -C $(TESTDIR)

run-test:
	@ ./runtest $(TESTDIR)/testenc.signed.so

distclean: clean
	rm -rf *.wraptest
