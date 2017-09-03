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

ENCLAVEINCDIR = $(INCDIR)/enclave

INCLUDES += -I$(ENCLAVEINCDIR)

ifdef NEED_LIBCXX
NEED_LIBC=1
INCLUDES += -I$(ENCLAVEINCDIR)/libcxx
endif

ifdef NEED_LIBC
INCLUDES += -I$(ENCLAVEINCDIR)/libc
endif

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

__LIBENCLAVE += $(WA) $(LIBDIR)/enclave/libeoenclave.a $(NOWA)

ifdef WHOLE_ARCHIVE
    __LIBELIBCXX=$(WA) $(LIBDIR)/enclave/liboelibcxx.a $(NOWA)
    __LIBELIBC=$(WA) $(LIBDIR)/enclave/liboelibc.a $(NOWA)
else
    __LIBELIBCXX=$(LIBDIR)/enclave/liboelibcxx.a
    __LIBELIBC=$(LIBDIR)/enclave/liboelibc.a
endif

__LIBECRYPTO=$(LIBDIR)/enclave/libecrypto.a

LDFLAGS +=-Wl,--start-group
LDFLAGS += $(__LIBENCLAVE)
ifdef NEED_LIBCXX
LDFLAGS += $(__LIBELIBCXX)
endif
ifdef NEED_LIBC
LDFLAGS += $(__LIBELIBC)
endif
LDFLAGS +=-Wl,--end-group

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

__OBJECTS = $(SOURCES:.c=.o)
OBJECTS = $(__OBJECTS:.cpp=.o)

ifdef CSHLIB
build : $(CSHLIB).signed.so
else
build : $(CXXSHLIB).signed.so
endif

ifdef CXXSHLIB
$(CXXSHLIB).signed.so: $(CXXSHLIB).so
	$(BINDIR)/oesign $(CXXSHLIB).so $(SIGNCONF) $(KEYFILE)
	chmod +x $(CXXSHLIB).signed.so
endif

ifdef CXXSHLIB
$(CXXSHLIB).so: $(OBJECTS)
	g++ -o $(CXXSHLIB).so $(OBJECTS) $(LDFLAGS) $(EXTRA_LDFLAGS)
endif

ifdef CSHLIB
$(CSHLIB).signed.so: $(CSHLIB).so
	$(BINDIR)/oesign $(CSHLIB).so $(SIGNCONF) $(KEYFILE)
	chmod +x $(CSHLIB).signed.so
endif

ifdef CSHLIB
$(CSHLIB).so: $(OBJECTS)
	gcc -o $(CSHLIB).so $(OBJECTS) $(LDFLAGS) $(EXTRA_LDFLAGS)
endif

%.o: %.cpp
	$(CXX) -c $(CXXFLAGS) $(DEFINES) $(INCLUDES) -o $@ $<

%.o: %.c
	$(CC) -c $(CFLAGS) $(DEFINES) $(INCLUDES) -o $@ $<

clean:
	rm -f $(OBJECTS) $(CXXSHLIB).so $(CXXSHLIB).signed.so .depends

include $(TOP)/mak/depend.mak
