CC = gcc

##==============================================================================
##
## whole-archive:
##
##     Function to wrap a library between these flags:
##
##         -Wl,--whole-archive
##         -Wl,--no-whole-archive
##
##     This option is helpful in determining if a library has unresolved
##     references that might not otherwise be referenced.
##
##==============================================================================

define whole-archive
-Wl,--whole-archive $(1) -Wl,--no-whole-archive
endef

##==============================================================================
##
## Print error if any of these are undefined:
##
##     CSHLIB or CXXSHLIB
##     SOURCES
##     SIGNCONF
##     KEYFILE
##
##==============================================================================

ifndef CSHLIB
  ifndef CXXSHLIB
    $(error "please define CSHLIB or CXXSHLIB")
  endif
endif

ifndef SOURCES
$(error "please define SOURCES")
endif

ifndef SIGNCONF
$(error "please define SIGNCONF")
endif

ifndef KEYFILE
$(error "please define KEYFILE")
endif

##==============================================================================
##
## CFLAGS
##
##==============================================================================

CFLAGS += -Wall
CFLAGS += -Werror
CFLAGS += -g
CFLAGS += -O2
CFLAGS += -m64
CFLAGS += -nostdinc
CFLAGS += -fPIC
CFLAGS += -fno-stack-protector

##==============================================================================
##
## CXXFLAGS:
##
##==============================================================================

CXXFLAGS += $(CFLAGS)
CXXFLAGS += -std=c++11
CXXFLAGS += -nostdinc++

##==============================================================================
##
## INCLUDES:
##
##==============================================================================

INCLUDES += -I$(INCDIR)/enclave

##==============================================================================
##
## LDFLAGS:
##
##==============================================================================

LDFLAGS += -g
LDFLAGS += -Wl,--no-undefined
LDFLAGS += -nostdlib
LDFLAGS += -nodefaultlibs
LDFLAGS += -nostartfiles
LDFLAGS += -Wl,-Bstatic
LDFLAGS += -Wl,-Bsymbolic
LDFLAGS += -Wl,--export-dynamic
LDFLAGS += -Wl,-pie,-eOE_Main
LDFLAGS += -L$(LIBDIR)/enclave

##==============================================================================
##
## LIBRARIES:
##
##==============================================================================

LIBRARIES += -loeenclave

##==============================================================================
##
## OBJECTS:
##
##==============================================================================

__OBJECTS = $(SOURCES:.c=.o)
OBJECTS = $(__OBJECTS:.cpp=.o)

##==============================================================================
##
## CSHLIB:
## CXXSHLIB:
##
##==============================================================================

ifdef CSHLIB
__SHLIB=$(CSHLIB)
else
__SHLIB=$(CXXSHLIB)
endif

build : $(__SHLIB).signed.so

$(__SHLIB).signed.so: $(__SHLIB).so
	$(BINDIR)/oesign $(__SHLIB).so $(SIGNCONF) $(KEYFILE)
	chmod +x $(__SHLIB).signed.so

ifdef CSHLIB
$(CSHLIB).so: $(OBJECTS)
	gcc -o $(CSHLIB).so $(OBJECTS) $(LDFLAGS) $(LIBRARIES)
endif

ifdef CXXSHLIB
$(CXXSHLIB).so: $(OBJECTS)
	g++ -o $(CXXSHLIB).so $(OBJECTS) $(LDFLAGS) $(LIBRARIES)
endif

##==============================================================================
##
## Compile rules for C and C++
##
##==============================================================================

%.o: %.cpp
	g++ -c $(CXXFLAGS) $(DEFINES) $(INCLUDES) -o $@ $<

%.o: %.c
	gcc -c $(CFLAGS) $(DEFINES) $(INCLUDES) -o $@ $<

##==============================================================================
##
## clean:
##
##==============================================================================

clean:
	rm -f $(OBJECTS) $(__SHLIB).so $(__SHLIB).signed.so .depends

include $(TOP)/mak/depend.mak
