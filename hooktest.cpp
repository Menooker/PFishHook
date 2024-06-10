#include "PFishHook.h"
#include <pthread.h>
#include <stdio.h>
#include <dlfcn.h>
#include <stdlib.h>
#include <netdb.h>

typedef void (*quick_exit_t)(int status);
static quick_exit_t quick_exit_f = nullptr;

void quick_exit_call(int status) {
	printf("hook quick exit\n");
	quick_exit_f(status);
}

typedef void (*pthread_exit_t) (void *__retval);
static pthread_exit_t pthread_exit_f = nullptr;

void pthread_exit_call(void *__retval) {
	printf("hook pthread_exit\n");
	pthread_exit_f(__retval);
}

typedef void (*endprotoent_t)(void);
static endprotoent_t endprotoent_f = nullptr;

void endprotoent_call() {
	printf("hook endprotoent\n");
	endprotoent_f();
}

int main()
{
	HookStatus ret;
	/*
	Dump of assembler code for function quick_exit:
	0x00007ffff78434b0 <+0>:     48 8d 35 49 a1 38 00    lea    0x38a149(%rip),%rsi        # 0x7ffff7bcd600 <__quick_exit_funcs>
	0x00007ffff78434b7 <+7>:     48 83 ec 08     sub    $0x8,%rsp
	0x00007ffff78434bb <+11>:    31 d2   xor    %edx,%edx
	0x00007ffff78434bd <+13>:    e8 4e fa ff ff  callq  0x7ffff7842f10 <__run_exit_handlers>
	*/
	void* quick_exit_handler = dlsym(RTLD_NEXT, "quick_exit");
	ret = HookIt(quick_exit_handler, (void **)&quick_exit_f, (void *)quick_exit_call);
	if (ret != FHSuccess) {
		printf("hook quick_exit fail%d\n", ret);
	}
	// UnHook(quick_exit_handler, (void*)quick_exit_f);

	/*
	Dump of assembler code for function __pthread_exit:
	0x00007ffff791dea0 <+0>:     sub    $0x8,%rsp
	0x00007ffff791dea4 <+4>:     mov    0x2b4886(%rip),%eax        # 0x7ffff7bd2730 <__libc_pthread_functions_init>
	0x00007ffff791deaa <+10>:    test   %eax,%eax
	0x00007ffff791deac <+12>:    jne    0x7ffff791deb5 <__pthread_exit+21>
	*/
	void* pthread_exit_handler = dlsym(RTLD_NEXT, "pthread_exit");
	ret = HookIt(pthread_exit_handler, (void **)&pthread_exit_f, (void *)pthread_exit_call);
	if (ret != FHSuccess) {
		printf("hook pthread_exit fail%d\n", ret);
	}

	/*
	Dump of assembler code for function endprotoent:
	0x00007ffff7924ca0 <+0>:     48 83 3d 80 c7 2a 00 00 cmpq   $0x0,0x2ac780(%rip)        # 0x7ffff7bd1428 <startp>
	0x00007ffff7924ca8 <+8>:     0f 84 b5 00 00 00       je     0x7ffff7924d63 <endprotoent+195>
	*/
	void* endprotoent_handler = dlsym(RTLD_NEXT, "endprotoent");
	ret = HookIt(endprotoent_handler, (void **)&endprotoent_f, (void *)endprotoent_call);
	if (ret != FHSuccess) {
		printf("hook endprotoent fail%d\n", ret);
	}

	/*
	Dump of assembler code for function htons:
	0x00007ffff79223a0 <+0>:     89 f8   mov    %edi,%eax
	0x00007ffff79223a2 <+2>:     66 c1 c8 08     ror    $0x8,%ax
	0x00007ffff79223a6 <+6>:     c3      retq
	*/
	// we must reject the hook of htons, because it is too small to be hooked

	quick_exit(0);
}