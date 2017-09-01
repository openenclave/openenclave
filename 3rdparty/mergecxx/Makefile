include ../../mak/defs.mak

.PHONY: lib

TARGET = $(LIBDIR)/enclave/liboelibcxx.a

TMPDIR = $(LIBDIR)/tmp

all: clean
	ar x $(LIBDIR)/tmp/libcxxrt.a
	ar x $(LIBDIR)/tmp/libunwind.a
	ar x $(LIBDIR)/tmp/libcxx.a
	ar r $(TARGET) *.o

clean:
	rm -rf *.o $(TARGET)

tests:

distclean:
