TOP = ../../..

TARGET = $(TOP)/lib/tmp/libllvmcxx.a

CXXFLAGS += -w
CXXFLAGS += -nostdinc
CXXFLAGS += -nostdinc++
CXXFLAGS += -std=c++11
CXXFLAGS += -fPIC
CXXFLAGS += -DLIBCXXRT

DEFINES += -D_LIBCPP_PROVIDES_DEFAULT_RUNE_TABLE

INCLUDES += -I../include 
INCLUDES += -I$(TOP)/include/enclave
INCLUDES += -I$(TOP)/3rdparty/libcxxrt/libcxxrt/src

SOURCES += algorithm.cpp
SOURCES += any.cpp
SOURCES += bind.cpp
SOURCES += exception.cpp
SOURCES += functional.cpp
SOURCES += hash.cpp
SOURCES += memory.cpp
SOURCES += new.cpp
SOURCES += optional.cpp
SOURCES += regex.cpp
SOURCES += stdexcept.cpp
SOURCES += string.cpp
SOURCES += typeinfo.cpp
SOURCES += utility.cpp
SOURCES += valarray.cpp
SOURCES += variant.cpp
SOURCES += vector.cpp
SOURCES += system_error.cpp
SOURCES += chrono.cpp
SOURCES += random.cpp
SOURCES += locale.cpp
SOURCES += ios.cpp
SOURCES += mutex.cpp
SOURCES += condition_variable.cpp
SOURCES += thread.cpp
SOURCES += future.cpp
SOURCES += shared_mutex.cpp
SOURCES += iostream.cpp
SOURCES += strstream.cpp

__BROKEN_SOURCES += debug.cpp

OBJECTS = $(SOURCES:.cpp=.o)

__BROKEN_OBJECTS = $(__BROKEN_SOURCES:.cpp=.o)

force: $(OBJECTS)
	mkdir -p $(TOP)/lib
	rm -rf $(TARGET)
	ar r $(TARGET) $(OBJECTS)

%.o : %.cpp
	g++ -c $(CXXFLAGS) $(DEFINES) $(INCLUDES) -o $@ $<

clean:
	rm -f $(TARGET) $(OBJECTS) $(__BROKEN_OBJECTS)

xxx:
	echo $(INCLUDES)
