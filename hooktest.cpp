#include "PFishHook.h"
#include <Zydis/Zydis.h>
#include <stdio.h>
#include <stdint.h>

int main();

asm("testfunc:\n\
ja gofurther2\n\
gofurther:\n\
	call  main\n\
gofurther2:\n\
	call  main\n\
");
extern "C" void testfunc();

void(*poldfunc)();
void test_replace()
{
	return poldfunc();
}

asm(R"(testfunc2:
jne gofurther3
cmpl   $0x0,0x10(%rip)
ja gofurther4
ja gofurther5
gofurther3:
	call  main
gofurther4:
	call  main
gofurther5:
	call  main
)");
extern "C" void testfunc2();

extern "C" void testfunc_lea();
asm(R"(testfunc_lea:
lea 0x123450(%rip),%ecx
lea 0x123450(%rip),%rcx
ret
)");

extern "C" void testfunc_call();
asm(R"(testfunc_call:
jmp main
call  main
ret
)");

void(*poldfunc2)();
void(*poldfunc3)();
void(*poldfunc4)();
void test_replace2()
{
	return poldfunc2();
}





int main()
{
	ZydisFormatter formatter;
	ZydisFormatterInit(&formatter, ZYDIS_FORMATTER_STYLE_INTEL);
	//ZydisFormatterSetProperty(&formatter, ZYDIS_FORMATTER_PROP_ADDR_FORMAT, ZYDIS_ADDR_FORMAT_RELATIVE_SIGNED);
	ZydisDecoder decoder;
	ZydisDecoderInit(
		&decoder,
		ZYDIS_MACHINE_MODE_LONG_64,
		ZYDIS_ADDRESS_WIDTH_64);

	typedef void(*functype)();
	auto disas = [&](functype f, int sz)
	{
		uint8_t* readPointer = (uint8_t*)f;
		ZydisDecodedInstruction instruction;
		while (ZYDIS_SUCCESS(ZydisDecoderDecodeBuffer(
			&decoder, readPointer, 128, (uint64_t)readPointer, &instruction)))
		{
			char buffer[256];
			ZydisFormatterFormatInstruction(
				&formatter, &instruction, buffer, sizeof(buffer));
			printf("0x%p: %s\n", readPointer, buffer);
			sz--;
			if (sz <= 0)
				break;
			readPointer += instruction.length;
		}
		printf("==============================\n");
	};

	
	auto runtest = [&](const char* name,functype target, functype* old, functype newfunc)
	{
		printf("==============================\n%s\n==============================\nBefore Hook:\n", name);
		disas(target, 5);
		auto ret = HookIt((void*)target, (void**)old, (void*)newfunc);
		printf("Hook status=%d\n", ret);
		if (ret == FHSuccess)
		{
			printf("After Hook:\n");
			disas(target, 7);
			printf("\nShadow Func:\n");
			disas(*old, 10);
		}
	};

	printf("main=%p\ntest_replace=%p\ntest_replace2=%p\n", main, test_replace, test_replace2);

	runtest("testfunc", testfunc, &poldfunc, test_replace);
	runtest("testfunc2", testfunc2, &poldfunc2, test_replace2);
	runtest("testfunc_lea", testfunc_lea, &poldfunc3, test_replace2);
	runtest("testfunc_call", testfunc_call, &poldfunc4, test_replace2);
	return 0;
}