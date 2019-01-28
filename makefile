.PHONY:all clean directories header

PWD_DIR=$(shell pwd)
INCLUDE=$(PWD_DIR)
OUT_DIR=$(PWD_DIR)/bin
OUT_INC_DIR=$(PWD_DIR)/include
LIBPATH=$(PWD_DIR)

CXX ?= g++
CXXFLAGS ?= -std=c++11  -O3 -I$(INCLUDE) -L$(LIBPATH)
LIBS ?= 

all: directories lib header

directories:
	mkdir -p ${OUT_DIR}
	mkdir -p ${OUT_INC_DIR}



inline_hook.o: inline_hook.cpp
	$(CXX) -c $^ -fPIC $(CXXFLAGS)

lib:  inline_hook.o 
	cp $(LIBPATH)/libZydis.a ${OUT_DIR}
	cd ${OUT_DIR} && ar x libZydis.a
	ar rcs ${OUT_DIR}/libPFishHook.a inline_hook.o ${OUT_DIR}/*.o
	rm ${OUT_DIR}/*.o

header: PFishHook.h
	cp $(PWD_DIR)/PFishHook.h $(OUT_INC_DIR)/PFishHook.h


test: hooktest.o lib
	g++ hooktest.o ${OUT_DIR}/libPFishHook.a -L$(LIBPATH)  -lZydis -o hooktest

clean:
	rm -f *.o
	rm -f ${OUT_DIR}/libPFishHook.a
	rm -f ${OUT_INC_DIR}/PFishHook.h


