#include "PFishHook.h"
#include <stdio.h>
int main();
__attribute__((naked)) void testfunc()
{
	//asm("cmpl   $0x0,0x7ffff10(%rip)");
	//asm("cmpl   $0x0,0x10(%rip)");
	asm goto ("jmp %l0\n"
		: /* no output */
	: /* no input */
		: /* no clobber */
		: gofurther);
	asm goto ("ja %l0\n"
		: /* no output */
	: /* no input */
		: /* no clobber */
		: gofurther2);
gofurther:
	asm("call  main");
gofurther2:
	asm("call  main");

}

void(*poldfunc)();
void test_replace()
{
	return poldfunc();
}


__attribute__((naked)) void testfunc2()
{
	asm("cmpl   $0x0,0x10(%rip)");
	//asm("cmpl   $0x0,0x10(%rip)");
	asm goto ("jne %l0\n"
		: /* no output */
	: /* no input */
		: /* no clobber */
		: gofurther);
	asm goto ("ja %l0\n"
		: /* no output */
	: /* no input */
		: /* no clobber */
		: gofurther2);
	asm goto ("ja %l0\n"
		: /* no output */
	: /* no input */
		: /* no clobber */
		: gofurther3);
gofurther:
	asm("call  main");
gofurther2:
	asm("call  main");
gofurther3:
	asm("call  main");

}

void(*poldfunc2)();
void test_replace2()
{
	return poldfunc2();
}

int main()
{
	printf("%d\n",HookIt((void*)testfunc, (void**)&poldfunc, (void*)test_replace));
	printf("%d\n", HookIt((void*)testfunc2, (void**)&poldfunc2, (void*)test_replace2));
	return 0;
}