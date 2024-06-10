#pragma once

enum HookStatus
{
	FHSuccess,
	FHDecodeFailed,
	FHMprotectFail,
	FHAllocFailed,
	FHPatchFailed,
	FHEncodeFailed,
};

#ifdef __cplusplus 
extern "C" {
#endif
 HookStatus HookIt(void* oldfunc, void** poutold, void* newfunc);
 HookStatus UnHook(void* oldfunc, void* func);

#ifdef __cplusplus 
}
#endif 
