#pragma once
enum HookStatus
{
	FHSuccess,
	FHDecodeFailed,
	FHMprotectFail,
	FHAllocFailed,
	FHPatchFailed,
};

extern "C" HookStatus HookIt(void* oldfunc, void** poutold, void* newfunc);
extern "C" HookStatus UnHook(void* oldfunc, void* func);