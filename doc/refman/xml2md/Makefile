include ../../../mak/defs.mak

TARGET=$(BINDIR)/xml2md

SOURCES=$(wildcard *.cpp)

all:
	g++ -Wall -o $(TARGET) $(SOURCES) -lexpat

clean:
	rm -f $(TARGET)

distclean:

depend:
