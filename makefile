.PHONY:all clean directories header

PWD_DIR=$(shell pwd)
INCLUDE=$(PWD_DIR)
OUT_DIR=$(PWD_DIR)/bin
OUT_INC_DIR=$(PWD_DIR)/include
LIBPATH=$(PWD_DIR)

CXX ?= g++
CXXFLAGS ?= -std=c++11 -g  -O2 -I$(INCLUDE) -L$(LIBPATH)
LIBS ?= 

all: directories lib header

directories:
	mkdir -p ${OUT_DIR}
	mkdir -p ${OUT_INC_DIR}



inline_hook.o: inline_hook.cpp
	$(CXX) -c $^ -fPIC $(CXXFLAGS)

lib:  inline_hook.o 
	ar rcs ${OUT_DIR}/libPFishHook.a inline_hook.o 

header: PFishHook.h
	cp $(PWD_DIR)/PFishHook.h $(OUT_INC_DIR)/PFishHook.h



clean:
	rm -f *.o
	rm -f ${OUT_DIR}/libPFishHook.a
	rm -f ${OUT_INC_DIR}/PFishHook.h


