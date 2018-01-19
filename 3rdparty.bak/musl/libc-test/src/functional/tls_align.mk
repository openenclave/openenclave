$(N).LDLIBS := $(B)/$(D)/tls_align_dso.so
$(N)-static.LDLIBS := $(B)/$(D)/tls_align_dso.o

$(B)/$(N).exe: $(B)/$(D)/tls_align_dso.so
$(B)/$(N)-static.exe: $(B)/$(D)/tls_align_dso.o

