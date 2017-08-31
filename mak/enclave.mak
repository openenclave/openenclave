CC = gcc

CXX = g++

CFLAGS += -Wall
CFLAGS += -Werror
CFLAGS += -g
CFLAGS += -O0
CFLAGS += -m64
CFLAGS += -nostdinc
#CFLAGS += -Wno-attributes
#CFLAGS += -fvisibility=hidden
#CFLAGS += -fpie
CFLAGS += -fPIC
CFLAGS += -fno-stack-protector

CXXFLAGS += $(CFLAGS)
CXXFLAGS += -std=c++11
CXXFLAGS += -nostdinc++

#CXXFLAGS += -fno-rtti
#CXXFLAGS += -fno-exceptions
#CXXFLAGS += -fno-enforce-eh-specs
#CXXFLAGS += -fno-threadsafe-statics

INCLUDES += -I$(ENCLAVEINCDIR)

CXX_INCLUDES += -I$(ENCLAVEINCDIR)/cxx $(INCLUDES)

DEFINES += -DOE_BUILD_ENCLAVE

LDFLAGS += -g
LDFLAGS += -Wl,--no-undefined
LDFLAGS += -nostdlib
LDFLAGS += -nodefaultlibs
LDFLAGS += -nostartfiles
LDFLAGS += -Wl,-Bstatic
LDFLAGS += -Wl,-Bsymbolic
LDFLAGS += -Wl,--export-dynamic
LDFLAGS += -Wl,-pie,-eOE_Main

WA=-Wl,--whole-archive
NOWA=-Wl,--no-whole-archive

__LIBENCLAVE += $(WA) $(LIBDIR)/enclave/libenclave.a $(NOWA)

ifdef WHOLE_ARCHIVE
    __LIBELIBCXX=$(WA) $(LIBDIR)/enclave/libelibcxx.a $(NOWA)
    __LIBELIBC=$(WA) $(LIBDIR)/enclave/libelibc.a $(NOWA)
else
    __LIBELIBCXX=$(LIBDIR)/enclave/libelibcxx.a
    __LIBELIBC=$(LIBDIR)/enclave/libelibc.a
endif

__LIBECRYPTO=$(LIBDIR)/enclave/libecrypto.a

LDFLAGS +=-Wl,--start-group
LDFLAGS += $(__LIBENCLAVE)
LDFLAGS += $(__LIBELIBCXX)
LDFLAGS += $(__LIBELIBC)
ifdef NEED_ECRYPTO
LDFLAGS += $(__LIBECRYPTO)
endif
LDFLAGS +=-Wl,--end-group

ifndef CXXSHLIB
$(error "please define CXXSHLIB")
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

__OBJECTS = $(SOURCES:.c=.o)
OBJECTS = $(__OBJECTS:.cpp=.o)

build : $(CXXSHLIB).signed.so

$(CXXSHLIB).signed.so: $(CXXSHLIB).so
	$(BINDIR)/oesign $(CXXSHLIB).so $(SIGNCONF) $(KEYFILE)
	chmod +x $(CXXSHLIB).signed.so

$(CXXSHLIB).so: $(OBJECTS)
	g++ -o $(CXXSHLIB).so $(OBJECTS) $(LDFLAGS) $(EXTRA_LDFLAGS)

%.o: %.cpp
	$(CXX) -c $(CXXFLAGS) $(DEFINES) $(CXX_INCLUDES) -o $@ $<

%.o: %.c
	$(CC) -c $(CFLAGS) $(DEFINES) $(INCLUDES) -o $@ $<

clean:
	rm -f $(OBJECTS) $(CXXSHLIB).so $(CXXSHLIB).signed.so .depends

include $(TOP)/mak/depend.mak
