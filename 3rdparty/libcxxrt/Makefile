include ../../mak/defs.mak

TARGET = $(LIBDIR)/tmp/libcxxrt.a

CACHEFILE = $(CACHEDIR)/libcxxrt.tar.gz

all: 
	$(MAKE) libcxxrt 
	$(MAKE) configure
	$(MAKE) -C libcxxrt
	cp ./libcxxrt/lib/libcxxrt.a $(TARGET)

delete:
	ar -d $(TARGET) guard.cc.o
	ar -d $(TARGET) exception.cc.o
	ar -d $(TARGET) dynamic_cast.cc.o
	ar -d $(TARGET) stdexcept.cc.o
	ar -d $(TARGET) typeinfo.cc.o
	ar -d $(TARGET) memory.cc.o
	ar -d $(TARGET) auxhelper.cc.o
	ar -d $(TARGET) libelftc_dem_gnu3.c.o

OPTS = --enable-cxx-exceptions --enable-msabi-support

CFLAGS=-include $(TOP)/3rdparty/libcxxrt/stubs.h -fPIC

CXXFLAGS=$(CFLAGS)

configure:
	( cd libcxxrt; cmake CMakeLists.txt -DCMAKE_CXX_FLAGS="$(CXXFLAGS)" -DCMAKE_C_FLAGS="$(CFLAGS)" )

clean:
	@ $(MAKE) -s clean-silent

clean-silent:
	-@ rm -f $(TARGET)
	-@ $(MAKE) -C libcxxrt clean 2> /dev/null

libcxxrt:
	$(MAKE) $(CACHEFILE)
	tar zxf $(CACHEFILE)

$(CACHEFILE):
	git clone https://github.com/pathscale/libcxxrt
	rm -rf libcxxrt/.git
	tar zcf $(CACHEFILE) libcxxrt
	rm -rf libcxxrt

distclean:
	rm -rf libcxxrt

depend:
