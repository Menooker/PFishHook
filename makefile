.PHONY:all clean directories header

PWD_DIR=$(shell pwd)
INCLUDE=$(PWD_DIR)
OUT_DIR=$(PWD_DIR)/bin
OUT_INC_DIR=$(PWD_DIR)/include
LIBPATH=$(PWD_DIR)
ABS_LIBPATH= $(realpath $(LIBPATH))

CXX ?= g++
CXXFLAGS ?= -std=c++11 -O2 -I$(INCLUDE) -L$(LIBPATH)
LIBS ?= 

all: directories ${OUT_DIR}/libPFishHook.a header

directories:
	mkdir -p ${OUT_DIR}
	mkdir -p ${OUT_INC_DIR}



inline_hook.o: inline_hook.cpp
	$(CXX) -c $^ -fPIC $(CXXFLAGS)

${OUT_DIR}/libPFishHook.a:  inline_hook.o 
	cd ${OUT_DIR} && ar x ${ABS_LIBPATH}/libZydis.a
	ar rcs ${OUT_DIR}/libPFishHook.a inline_hook.o ${OUT_DIR}/*.o
	rm ${OUT_DIR}/*.o

${OUT_DIR}/libPFishHook_NoZydis.a:  inline_hook.o 
	ar rcs ${OUT_DIR}/libPFishHook_NoZydis.a inline_hook.o

header: PFishHook.h
	cp $(PWD_DIR)/PFishHook.h $(OUT_INC_DIR)/PFishHook.h


hooktest: hooktest.o ${OUT_DIR}/libPFishHook.a
	g++ hooktest.o ${OUT_DIR}/libPFishHook.a -L$(LIBPATH) -o hooktest

clean:
	rm -f *.o
	rm -f ${OUT_DIR}/libPFishHook.a
	rm -f ${OUT_INC_DIR}/PFishHook.h
