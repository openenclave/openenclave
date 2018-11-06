OBJECTS = main.o BufferTest.o TrustedAppTest.o OEEnclaveTest.o OEHostTest.o SocketsTest.o oetests_u.o

EDL_PATH = ../../src
EDL_INC_PATH = ../../include
OE_EDL_PATH = $(OE_PATH)/openenclave

GTEST_PATH = ../../../3rdparty/googletest/googletest
OE_PATH = ../../../include

DEFINES = -DUNTRUSTED_CODE -DUSE_OPTEE -D_DEBUG -DLINUX
INCLUDES =                          \
    -I../../include/optee/Untrusted \
    -I../../include/                \
    -I../../include/linux           \
    -I$(SGX_SDK)/include            \
    -I$(GTEST_PATH)/include         \
    -I$(OE_PATH)

CFLAGS = $(DEFINES) $(INCLUDES) -g
CXFLAGS = $(CFLAGS) -std=c++11

LDFLAGS =                                        \
    -L../gtest                                   \
    -L../../src/Untrusted/linux                  \
    -L../../../3rdparty/optee_client/out/libteec \
    -l:libgtest.a                                \
    -l:oehost.a                                  \
    -l:libteec.a                                 \
    -lpthread

CC = $(CROSS_COMPILE)gcc
CX = $(CROSS_COMPILE)g++
AR = $(CROSS_COMPILE)ar

APP_NAME = oetests_host

oetests_host: $(OBJECTS)
	@echo " [LD]\toetests_host"
	@$(CX) -o $(APP_NAME) $(OBJECTS) $(LDFLAGS)

oetests_u.h oetests_u.c: $(EDL_PATH)/TcpsCalls.edl \
                         $(EDL_PATH)/TcpsFile.edl  \
                         $(OE_EDL_PATH)/socket.edl \
                        ../oetests.edl
	@echo " [EDGE]\oetests.edl"
	@$(OEEDGER8R) --untrusted --search-path "$(EDL_INC_PATH):$(OE_PATH)" \
	                                        "../oetests.edl"

main.o: main.cpp
	@echo " [CC]\t$@"
	@$(CX) $(CFLAGS) $(CXFLAGS) -c -o $@ $<

BufferTest.o: BufferTest.cpp oetests_u.h
	@echo " [CC]\t$@"
	@$(CX) $(CFLAGS) $(CXFLAGS) -c -o $@ $<

TrustedAppTest.o: TrustedAppTest.cpp oetests_u.h
	@echo " [CC]\t$@"
	@$(CX) $(CFLAGS) $(CXFLAGS) -c -o $@ $<

OEEnclaveTest.o: OEEnclaveTest.cpp oetests_u.h
	@echo " [CC]\t$@"
	@$(CX) $(CFLAGS) $(CXFLAGS) -c -o $@ $<

OEHostTest.o: OEHostTest.cpp oetests_u.h
	@echo " [CC]\t$@"
	@$(CX) $(CFLAGS) $(CXFLAGS) -c -o $@ $<

SocketsTest.o: SocketsTest.cpp oetests_u.h
	@echo " [CC]\t$@"
	@$(CX) $(CFLAGS) $(CXFLAGS) -c -o $@ $<

oetests_u.o: oetests_u.c
	@echo " [CC]\t$@"
	@$(CC) $(CFLAGS) -include sal_unsup.h -include stddef.h -c -o $@ $<

.PHONY: clean
clean:
	@rm -f $(APP_NAME) oetests_u.h oetests_u.c $(OBJECTS)
	@echo "Done."
