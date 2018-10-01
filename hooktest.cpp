#include "PFishHook.h"
#include <stdio.h>
int main();
__attribute__((naked)) void testfunc()
{
	//asm("cmpl   $0x0,0x7ffff10(%rip)");
	//asm("cmpl   $0x0,0x10(%rip)");
	asm goto ("ja %l0\n"
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

__attribute__((naked)) void testfunc_lea()
{
	asm("lea 0x123450(%rip),%ecx ");
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
void(*poldfunc3)();
void test_replace2()
{
	return poldfunc2();
}

typedef ssize_t(*ptrread)(int fd, void *buf, size_t nbytes);
ptrread oldread;

extern "C" ssize_t myread(int fd, void *buf, size_t nbytes)
{
	return 0;
}

int main()
{
	printf("%d\n",HookIt((void*)testfunc, (void**)&poldfunc, (void*)test_replace));
	printf("%d\n", HookIt((void*)testfunc2, (void**)&poldfunc2, (void*)test_replace2));
	printf("%d\n", HookIt((void*)testfunc_lea, (void**)&poldfunc3, (void*)test_replace2));
	
/*	void* pread = dlsym(RTLD_NEXT, "read");
	if (!pread)
	{
		fprintf(stderr, "read not found\n");
		exit(1);
	}
	HookStatus ret;
	if ((ret = HookIt(pread, (void**)&oldread, (void*)myread)) != 0)
	{
		fprintf(stderr, "Hook error %d\n", ret);
		exit(1);
	}*/
	return 0;
}