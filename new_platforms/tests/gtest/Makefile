# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

OBJECTS = gtest-all.o gtest_main.o

GTEST_DIR = ../../../3rdparty/googletest/googletest

CFLAGS = -isystem ${GTEST_DIR}/include -I${GTEST_DIR} -g

LIB_NAME = libgtest.a

CX = $(CROSS_COMPILE)g++
AR = $(CROSS_COMPILE)ar

libgtest.a: $(OBJECTS)
	@echo " [AR]\tlibgtest.a"
	@$(AR) rcs $(LIB_NAME) $(OBJECTS)

gtest-all.o: ${GTEST_DIR}/src/gtest-all.cc
	@echo " [CX]\t$@"
	@$(CX) $(CFLAGS) -c -o $@ $<

gtest_main.o: ${GTEST_DIR}/src/gtest_main.cc
	@echo " [CX]\t$@"
	@$(CX) $(CFLAGS) -c -o $@ $<

.PHONY: clean
clean:
	@rm -f $(LIB_NAME) $(OBJECTS)
	@echo "Done."
