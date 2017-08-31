include ../mak/defs.mak

CXXFLAGS = -Wall -Werror

PROGRAM=$(BINDIR)/oegen

INCLUDES = -I$(HOSTINCDIR)

SOURCES +=files.cpp
SOURCES +=generator.cpp
SOURCES +=lexer.cpp
SOURCES +=main.cpp
SOURCES +=objects.cpp
SOURCES +=parser.cpp
SOURCES +=types.cpp

LDFLAGS = -lcrypto

include $(MAKDIR)/program.mak
