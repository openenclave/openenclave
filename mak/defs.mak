TOP=$(shell dirname $(abspath $(dir $(word 2, $(MAKEFILE_LIST)))))

-include $(HOME)/enc.mak

CC=gcc
CXX=g++
MAKDIR=$(TOP)/mak
INCDIR=$(TOP)/include
LIBDIR=$(TOP)/lib
BINDIR=$(TOP)/bin
TMPDIR=$(TOP)/tmp

$(shell mkdir -p $(INCDIR))

$(shell mkdir -p $(LIBDIR))
$(shell mkdir -p $(LIBDIR)/tmp)
$(shell mkdir -p $(LIBDIR)/enclave)
$(shell mkdir -p $(LIBDIR)/host)
$(shell mkdir -p $(TMPDIR))

$(shell mkdir -p $(BINDIR))

MEMCHECK=valgrind --tool=memcheck --leak-check=full

CACHEGRIND=valgrind --tool=cachegrind --cachegrind-out-file=cachegrind.out
CG_ANNOTATE=cg_annotate --auto=yes $(CG_ANNOTATE_INCLUDES) cachegrind.out

CALLGRIND=valgrind --tool=callgrind --callgrind-out-file=callgrind.out
CALLGRIND_ANNOTATE=callgrind_annotate $(CALLGRIND_ANNOTATE_INCLUDES) callgrind.out

define NEWLINE


endef

TRUE=1

##==============================================================================
##
## HAVE_SGX
##
##     Use the oesgx utility (if already compiled) to determine whether the
##     CPU supports SGX. If so, set the HAVE_SGX variable as follows:
##
##         HAVE_SGX=1 -- SGX-1 is supported
##         HAVE_SGX=2 -- SGX-2 is supported
##
##==============================================================================

__OESGX=$(shell $(BINDIR)/oesgx 2> /dev/null)

ifeq ($(__OESGX),1)
HAVE_SGX=1
endif

ifeq ($(__OESGX),2)
HAVE_SGX=2
endif

