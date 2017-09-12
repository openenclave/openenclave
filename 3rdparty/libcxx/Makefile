include ../../mak/defs.mak

CXXFLAGS += -w
CXXFLAGS += -nostdinc
CXXFLAGS += -nostdinc++
CXXFLAGS += -std=c++14
CXXFLAGS += -fPIC

INCLUDES += -Ilibcxx/include
INCLUDES += -Ilibcxx/src
INCLUDES += -I$(TOP)/3rdparty/libcxxrt/libcxxrt/src
INCLUDES += -I$(INCDIR)
INCLUDES += -I$(INCDIR)/openenclave/libc

DEFINES += -DLIBCXXRT
DEFINES += -D_LIBCPP_PROVIDES_DEFAULT_RUNE_TABLE

SOURCES += $(wildcard *.cpp)
SOURCES += libcxx/src/algorithm.cpp
SOURCES += libcxx/src/any.cpp
SOURCES += libcxx/src/bind.cpp
SOURCES += libcxx/src/chrono.cpp
SOURCES += libcxx/src/condition_variable.cpp
#SOURCES += libcxx/src/debug.cpp
SOURCES += libcxx/src/exception.cpp
SOURCES += libcxx/src/functional.cpp
SOURCES += libcxx/src/future.cpp
SOURCES += libcxx/src/hash.cpp
SOURCES += libcxx/src/ios.cpp
SOURCES += libcxx/src/iostream.cpp
SOURCES += libcxx/src/locale.cpp
SOURCES += libcxx/src/memory.cpp
SOURCES += libcxx/src/mutex.cpp
SOURCES += libcxx/src/new.cpp
SOURCES += libcxx/src/optional.cpp
SOURCES += libcxx/src/random.cpp
SOURCES += libcxx/src/regex.cpp
SOURCES += libcxx/src/shared_mutex.cpp
SOURCES += libcxx/src/stdexcept.cpp
SOURCES += libcxx/src/string.cpp
SOURCES += libcxx/src/strstream.cpp
SOURCES += libcxx/src/system_error.cpp
SOURCES += libcxx/src/thread.cpp
SOURCES += libcxx/src/typeinfo.cpp
SOURCES += libcxx/src/utility.cpp
SOURCES += libcxx/src/valarray.cpp
SOURCES += libcxx/src/variant.cpp
SOURCES += libcxx/src/vector.cpp

TARGET = $(LIBDIR)/tmp/libcxx.a

CACHEFILE = $(CACHEDIR)/libcxx.tar.gz

OBJECTS = $(SOURCES:.cpp=.o)

HEADER_INSTALL_DIRECTORY=$(INCDIR)/openenclave/libcxx

all: libcxx patch $(OBJECTS)
	@ rm -f $(TARGET)
	@ ar r $(TARGET) $(OBJECTS)
	@ $(MAKE) install

%.o: %.cpp
	$(CXX) -c $(CXXFLAGS) $(DEFINES) $(INCLUDES) -o $@ $<

clean:
	rm -f $(OBJECTS)

distclean: clean
	rm -rf libcxx
	rm -rf $(HEADER_INSTALL_DIRECTORY)
	
libcxx:
	$(MAKE) $(CACHEFILE)
	tar zxf $(CACHEFILE)
	cp libcxx/include/__config libcxx/include/__config_original

$(CACHEFILE):
	svn co http://llvm.org/svn/llvm-project/libcxx/trunk
	mv trunk libcxx
	tar zcf $(CACHEFILE) libcxx

patch:
	@ cp __config libcxx/include/__config

patch-old:
	@ ./sub libcxx/include/cstdlib
	@ ./sub libcxx/include/cstdio
	@ ./sub libcxx/include/cwchar
	@ ./sub libcxx/include/ctime
	@ ./sub libcxx/include/clocale

install:
	rm -rf $(HEADER_INSTALL_DIRECTORY)
	cp -r libcxx/include $(HEADER_INSTALL_DIRECTORY)

merge:
	(cd ../mergecxx; make )

depend:
