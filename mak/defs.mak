TOP=$(shell dirname $(abspath $(dir $(word 2, $(MAKEFILE_LIST)))))

-include $(HOME)/enc.mak

CC=gcc
CXX=g++
MAKDIR=$(TOP)/mak
INCDIR=$(TOP)/include
LIBDIR=$(TOP)/lib
BINDIR=$(TOP)/bin
TMPDIR=$(TOP)/tmp
CACHEDIR=$(TOP)/.cache

$(shell mkdir -p $(INCDIR))

$(shell mkdir -p $(LIBDIR))
$(shell mkdir -p $(LIBDIR)/tmp)
$(shell mkdir -p $(LIBDIR)/enclave)
$(shell mkdir -p $(LIBDIR)/host)
$(shell mkdir -p $(TMPDIR))
$(shell mkdir -p $(CACHEDIR))

$(shell mkdir -p $(BINDIR))

MEMCHECK=valgrind --tool=memcheck --leak-check=full

CACHEGRIND=valgrind --tool=cachegrind --cachegrind-out-file=cachegrind.out
CG_ANNOTATE=cg_annotate --auto=yes $(CG_ANNOTATE_INCLUDES) cachegrind.out

CALLGRIND=valgrind --tool=callgrind --callgrind-out-file=callgrind.out
CALLGRIND_ANNOTATE=callgrind_annotate $(CALLGRIND_ANNOTATE_INCLUDES) callgrind.out

define NEWLINE


endef

##==============================================================================
##
## Add ./scripts/ccache directory to path so it will find the gcc and g++
## scripts that prefix the ccache
##
##==============================================================================

export PATH := $(TOP)/scripts/ccache:$(PATH)

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

##==============================================================================
##
## SGX=1 -- disable simulation mode
## SIM=1 -- enable simulation mode
##
##==============================================================================

export OE_SIMULATION=

ifdef SGX
  ifneq ($(SGX),1)
    $(error SGX must be set to 1)
  endif
  ifdef SIM
    $(error incompatible switches: SGX and SIM)
  endif
  export OE_SIMULATION=0
endif

ifdef SIM
  ifneq ($(SIM),1)
    $(error SIM must be set to 1)
  endif
  ifdef SGX
    $(error incompatible switches: SIM and SGX)
  endif
  export OE_SIMULATION=1
endif

ifndef OE_SIMULATION
  ifdef HAVE_SGX
    export OE_SIMULATION=0
  else
    export OE_SIMULATION=1
  endif
endif
