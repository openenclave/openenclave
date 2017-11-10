include ../../../mak/defs.mak

PROGRAM = libchost

SOURCES = host.cpp

include $(TOP)/mak/host.mak

export OE_TOP=$(TOP)

CLEAN = $(wildcard *.wraptest)

WRAPTEST = $(TOP)/tests/wraptest/wraptest

TESTDIR = $(wildcard *.wraptest)
