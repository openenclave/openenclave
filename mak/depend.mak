
DEPEND_CSOURCES=$(filter %.c, $(SOURCES))
DEPEND_CXXSOURCES=$(filter %.cpp, $(SOURCES))

depend: rmdepend cdepend cxxdepend

rmdepend:
	@ rm -f .depends

cdepend:
	@ $(foreach i, $(DEPEND_CSOURCES), gcc -M -MG $(CFLAGS) $(DEFINES) $(INCLUDES) $(i) >> .depends $(NEWLINE) )

cxxdepend:
	@ $(foreach i, $(DEPEND_CXXSOURCES), g++ -M -MG $(CXXFLAGS) $(DEFINES) $(INCLUDES) $(i) >> .depends $(NEWLINE) )

-include .depends
