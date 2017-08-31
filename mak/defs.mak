TOP=$(shell dirname $(abspath $(dir $(word 2, $(MAKEFILE_LIST)))))

-include $(HOME)/enc.mak

CC=gcc
CXX=g++
MAKDIR=$(TOP)/mak
LIBDIR=$(TOP)/lib
BINDIR=$(TOP)/bin
INCDIR=$(TOP)/include
HOSTINCDIR=$(TOP)/include/host
ENCLAVEINCDIR=$(TOP)/include/enclave

$(shell mkdir -p $(BINDIR))
$(shell mkdir -p $(LIBDIR)/tmp)
$(shell mkdir -p $(LIBDIR)/enclave)
$(shell mkdir -p $(LIBDIR)/host)
$(shell mkdir -p $(INCDIR)/host)
$(shell mkdir -p $(INCDIR)/enclave)

$(shell rm -f $(ENCLAVEINCDIR)/oecommon)
$(shell ln -s ../oecommon $(ENCLAVEINCDIR)/oecommon)
$(shell rm -f $(HOSTINCDIR)/oecommon)
$(shell ln -s ../oecommon $(HOSTINCDIR)/oecommon)

$(shell rm -f $(ENCLAVEINCDIR)/oeinternal)
$(shell ln -s ../oeinternal $(ENCLAVEINCDIR)/oeinternal)
$(shell rm -f $(HOSTINCDIR)/oeinternal)
$(shell ln -s ../oeinternal $(HOSTINCDIR)/oeinternal)

MEMCHECK=valgrind --tool=memcheck --leak-check=full

CACHEGRIND=valgrind --tool=cachegrind --cachegrind-out-file=cachegrind.out
CG_ANNOTATE=cg_annotate --auto=yes $(CG_ANNOTATE_INCLUDES) cachegrind.out

CALLGRIND=valgrind --tool=callgrind --callgrind-out-file=callgrind.out
CALLGRIND_ANNOTATE=callgrind_annotate $(CALLGRIND_ANNOTATE_INCLUDES) callgrind.out

define NEWLINE


endef

TRUE=1
