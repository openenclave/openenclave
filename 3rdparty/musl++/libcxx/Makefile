CC=/opt/musl++/bin/musl-gcc
CXX=$(CURDIR)/musl-g++-stage1
RELEASE=RELEASE_700
URL=http://llvm.org/svn/llvm-project

all: checkout build

##==============================================================================
##
## checkout:
##
##==============================================================================

checkout: llvm libunwind libcxxabi libcxx

llvm:
	svn co $(URL)/llvm/trunk llvm

libunwind:
	svn co $(URL)/libunwind/trunk libunwind

libcxxabi:
	svn co  $(URL)/libcxxabi/trunk libcxxabi

libcxx:
	svn co  $(URL)/libcxx/tags/$(RELEASE)/final libcxx

distclean:
	rm -rf llvm libunwind libcxxabi libcxx
	rm -f __dso_handle.o

##==============================================================================
##
## build:
##
##==============================================================================

build: build-libunwind build-libcxxabi build-libcxx

LIBUNWIND_OPTS += -DCMAKE_C_COMPILER=$(CC)
LIBUNWIND_OPTS += -DLIBUNWIND_ENABLE_SHARED=0
LIBUNWIND_OPTS += -DLLVM_PATH=$(CURDIR)/llvm

build-libunwind: libunwind/build
	( cd libunwind; cd build; $(MAKE) )

libunwind/build:
	( cd libunwind; mkdir -p build; cd build; cmake ${LIBUNWIND_OPTS} .. )

LIBCXXABI_OPTS += -DCMAKE_C_COMPILER=$(CC)
LIBCXXABI_OPTS += -DCMAKE_SHARED_LINKER_FLAGS="-L$(CURDIR)/libunwind/build/lib"
LIBCXXABI_OPTS += -DLIBCXXABI_USE_LLVM_UNWINDER=1
LIBCXXABI_OPTS += -DLIBCXXABI_LIBUNWIND_PATH="$(CURDIR)/libunwind"
LIBCXXABI_OPTS += -DLIBCXXABI_LIBCXX_INCLUDES="$(CURDIR)/libcxx/include"
LIBCXXABI_OPTS += -DLLVM_PATH=$(CURDIR)/llvm

build-libcxxabi: libcxxabi/build
	( cd libcxxabi; cd build; $(MAKE) )

libcxxabi/build:
	( cd libcxxabi; mkdir -p build; cd build; cmake ${LIBCXXABI_OPTS} .. )

LIBCXX_OPTS += -DCMAKE_C_COMPILER=$(CC)
LIBCXX_OPTS += -DCMAKE_CXX_COMPILER=$(CXX)
LIBCXX_OPTS += -DLIBCXX_HAS_MUSL_LIBC=1
LIBCXX_OPTS += -DLIBCXX_HAS_GCC_S_LIB=0
LIBCXX_OPTS += -DLIBCXX_ENABLE_SHARED=0
LIBCXX_OPTS += -DLIBCXX_CXX_ABI=libcxxabi
LIBCXX_OPTS += -DLIBCXX_CXX_ABI_INCLUDE_PATHS="$(CURDIR)/libcxxabi/include"
LIBCXX_OPTS += -DLIBCXX_CXX_ABI_LIBRARY_PATH="$(CURDIR)/libcxxabi/build/lib"
LIBCXX_OPTS += -DLLVM_PATH=$(CURDIR)/llvm

build-libcxx: libcxx/build
	( cd libcxx; cd build; $(MAKE) )
	$(CXX) -fPIC -c __dso_handle.cpp
	ar rv ./libcxx/build/lib/libc++.a __dso_handle.o

libcxx/build:
	( cd libcxx; mkdir -p build; cd build; cmake ${LIBCXX_OPTS} .. )

##==============================================================================
##
## clean:
##
##==============================================================================

clean:
	rm -rf libunwind/build
	rm -rf libcxxabi/build
	rm -rf libcxx/build
	rm -f __dso_handle.o

##==============================================================================
##
## install:
##
##==============================================================================

install:
	mkdir -p /opt/musl++/include
	rm -rf /opt/musl++/include/libcxx
	cp -r ./libcxx/include /opt/musl++/include/libcxx
	cp -r ./libcxx/build/lib/libc++.a /opt/musl++/lib
	cp -r ./libcxxabi/build/lib/libc++abi.a /opt/musl++/lib
	cp -r ./libunwind/build/lib/libunwind.a /opt/musl++/lib

