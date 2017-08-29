include ../../mak/defs.mak

.PHONY: lib

TARGET = $(LIBDIR)/enclave/libelibcxx.a

TMPDIR = $(LIBDIR)/tmp

all: clean
	ls -l $(LIBDIR)/tmp/libcxxrt.a
	ls -l $(LIBDIR)/tmp/libunwind.a
	ls -l $(LIBDIR)/tmp/libllvmcxx.a
	ar x $(LIBDIR)/tmp/libcxxrt.a
	ar x $(LIBDIR)/tmp/libunwind.a
	ar x $(LIBDIR)/tmp/libllvmcxx.a
	ar r $(TARGET) *.o
	@ echo "Created $(TARGET)"

clean:
	rm -rf *.o $(TARGET)

tests:

distclean:
