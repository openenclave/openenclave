include ../../mak/defs.mak

CXXFLAGS += -w
CXXFLAGS += -nostdinc
CXXFLAGS += -nostdinc++
CXXFLAGS += -std=c++14
CXXFLAGS += -fPIC

INCLUDES += -Itrunk/include
INCLUDES += -Itrunk/src
INCLUDES += -I$(TOP)/3rdparty/libcxxrt/libcxxrt/src
INCLUDES += -I$(INCDIR)/enclave
INCLUDES += -I$(INCDIR)/enclave/libc

DEFINES += -DLIBCXXRT
DEFINES += -D_LIBCPP_PROVIDES_DEFAULT_RUNE_TABLE

SOURCES += $(wildcard *.cpp)
SOURCES += trunk/src/algorithm.cpp
SOURCES += trunk/src/any.cpp
SOURCES += trunk/src/bind.cpp
SOURCES += trunk/src/chrono.cpp
SOURCES += trunk/src/condition_variable.cpp
#SOURCES += trunk/src/debug.cpp
SOURCES += trunk/src/exception.cpp
SOURCES += trunk/src/functional.cpp
SOURCES += trunk/src/future.cpp
SOURCES += trunk/src/hash.cpp
SOURCES += trunk/src/ios.cpp
SOURCES += trunk/src/iostream.cpp
SOURCES += trunk/src/locale.cpp
SOURCES += trunk/src/memory.cpp
SOURCES += trunk/src/mutex.cpp
SOURCES += trunk/src/new.cpp
SOURCES += trunk/src/optional.cpp
SOURCES += trunk/src/random.cpp
SOURCES += trunk/src/regex.cpp
SOURCES += trunk/src/shared_mutex.cpp
SOURCES += trunk/src/stdexcept.cpp
SOURCES += trunk/src/string.cpp
SOURCES += trunk/src/strstream.cpp
SOURCES += trunk/src/system_error.cpp
SOURCES += trunk/src/thread.cpp
SOURCES += trunk/src/typeinfo.cpp
SOURCES += trunk/src/utility.cpp
SOURCES += trunk/src/valarray.cpp
SOURCES += trunk/src/variant.cpp
SOURCES += trunk/src/vector.cpp
SOURCES += libcxx_stubs.cpp

TARGET = $(LIBDIR)/tmp/libcxx.a

OBJECTS = $(SOURCES:.cpp=.o)

HEADER_INSTALL_DIRECTORY=$(INCDIR)/enclave/libcxx

all: trunk patch $(OBJECTS)
	@ rm -f $(TARGET)
	@ ar r $(TARGET) $(OBJECTS)
	@ $(MAKE) install

%.o: %.cpp
	$(CXX) -c $(CXXFLAGS) $(DEFINES) $(INCLUDES) -o $@ $<

clean:
	rm -f $(OBJECTS)

distclean: clean
	rm -rf trunk
	rm -rf $(HEADER_INSTALL_DIRECTORY)
	
trunk:
	svn co http://llvm.org/svn/llvm-project/libcxx/trunk
	cp trunk/include/__config trunk/include/__config_original

patch:
	@ cp __config trunk/include/__config
	@ sub trunk/include/cstdlib
	@ sub trunk/include/cstdio
	@ sub trunk/include/cwchar
	@ sub trunk/include/ctime
	@ sub trunk/include/clocale

install:
	rm -rf $(HEADER_INSTALL_DIRECTORY)
	cp -r trunk/include $(HEADER_INSTALL_DIRECTORY)
