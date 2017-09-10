include ../../mak/defs.mak

TARGET=$(BINDIR)/dox2md

SOURCES=$(wildcard *.cpp)

all:
	g++ -Wall -o $(TARGET) $(SOURCES) -lexpat

clean:
	rm -f $(TARGET)

distclean: clean

depend:
