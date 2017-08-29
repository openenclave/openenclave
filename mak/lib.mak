.PHONY: lib

ifndef LIB
$(error "Please define LIB")
endif

ifndef SOURCES
$(error "Please define SOURCES")
endif

CC = gcc

CFLAGS += -c -m64 -O2 -fPIC -Wno-attributes -Werror

CXX = g++

CXXFLAGS += $(CFLAGS) -std=c++11

__OBJECTS = $(SOURCES:.c=.o)
OBJECTS = $(__OBJECTS:.cpp=.o)

lib: $(LIB)

$(LIB): $(OBJECTS)
	ar rv $(LIB) $(OBJECTS)

%.o: %.c
	$(CC) -c $(CFLAGS) $(DEFINES) $(INCLUDES) -o $@ $<

%.o: %.cpp
	$(CXX) -c $(CXXFLAGS) $(DEFINES) $(INCLUDES) -o $@ $<

clean:
	rm -f $(LIB) $(OBJECTS) $(CLEAN)

