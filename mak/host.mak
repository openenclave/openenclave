.PHONY: host

ifndef PROGRAM
  $(error "Please define PROGRAM")
endif

ifndef SOURCES
  $(error "Please define SOURCES")
endif

INCLUDES = -I$(HOSTINCDIR)

CFLAGS += -Wall -Werror -g -O2 -fPIC

CXXFLAGS += $(CFLAGS)
CXXFLAGS += -std=c++11

__OBJECTS = $(SOURCES:.c=.o)
OBJECTS = $(__OBJECTS:.cpp=.o)

ifneq ($(__OBJECTS),$(OBJECTS))
  __COMPILER=$(CXX)
else
  __COMPILER=$(CC)
endif

LDFLAGS += -g -rdynamic -L$(LIBDIR)/host -loehost -lcrypto -ldl -lpthread

host:
	$(MAKE) $(PROGRAM)

$(PROGRAM): $(OBJECTS) $(LIBRARIES)
	$(__COMPILER) $(OBJECTS) -o $(PROGRAM) $(LIBRARIES) $(LDFLAGS)

%.o: %.c
	$(CC) -c $(CFLAGS) $(DEFINES) $(INCLUDES) -o $@ $<

%.o: %.cpp
	$(CXX) -c $(CXXFLAGS) $(DEFINES) $(INCLUDES) -o $@ $<

clean:
	rm -f $(PROGRAM) $(OBJECTS) $(CLEAN) .depends

include $(MAKDIR)/depend.mak
