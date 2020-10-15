#pragma once
#include <dlfcn.h>
#include <PFishHook.h>
#include <stdio.h>
#include <stdlib.h>
#include <utility>

#define def_name(_name,_ret_type,...) struct Name_##_name{ static constexpr char const* name = #_name;typedef _ret_type return_type; typedef OldFuncWrapper<Name_##_name,_ret_type,__VA_ARGS__> func_wrapper;};
#define def_name_no_arg(_name,_ret_type) struct Name_##_name{ static constexpr char const* name = #_name;typedef _ret_type return_type; typedef OldFuncWrapper<Name_##_name,_ret_type> func_wrapper;};
#define get_name(_name) Name_##_name;
#define auto_hook(_name, _func) AutoHook<Name_##_name, _func> __hook_auto_##_name;


extern bool init_called;
namespace FishHook
{

	template <typename TName, typename TRet, typename... TTypes>
	struct OldFuncWrapper
	{
		typedef TRet(*ptrFunc)(TTypes...);
		static ptrFunc old_func;
	};

	template <typename TName, typename TFunc, typename TRet, typename... TTypes>
	struct HookFunction
	{
		typedef typename TName::func_wrapper::ptrFunc ptrFunc;
		static TRet Func(TTypes... args)
		{
			ptrFunc& old_func = OldFuncWrapper<TName, TRet, TTypes...>::old_func;
			if (!old_func)
			{
				old_func = (ptrFunc)dlsym(RTLD_NEXT, TName::name);
				if (NULL == OldFuncWrapper<TName, TRet, TTypes...>::old_func) {
					fprintf(stderr, "Error in `dlsym`: %s\n", dlerror());
				}
			}
			if (!init_called)
			{
				return old_func(std::forward<TTypes>(args)...);
			}
			TFunc& func = *(TFunc*)(nullptr);
			return func(std::forward<TTypes>(args)...);
		}
	};

	template <typename TName, typename... TTypes>
	typename TName::return_type CallOld(TTypes... args)
	{
		return TName::func_wrapper::old_func(std::forward<TTypes>(args)...);
	}

	template <typename TName, typename TFunc, typename... TTypes>
	typename TName::return_type CallHooked(TFunc func, TTypes... args)
	{
		return HookFunction<TName, TFunc, typename TName::return_type, TTypes...>::Func(std::forward<TTypes>(args)...);
	}


	template <typename TName, typename TRet, typename... TTypes>
	typename OldFuncWrapper<TName, TRet, TTypes...>::ptrFunc OldFuncWrapper<TName, TRet, TTypes...>::old_func = nullptr;

	inline void* GetFuncAddress(void* handle, const char* name)
	{
		void* pfun = dlsym(handle, name);
		if (!pfun)
		{
			fputs(dlerror(), stderr);
			exit(1);
		}
		return pfun;
	}

	inline void _DoHook(void* oldfunc, void** poutold, void* newfunc)
	{
		HookStatus ret;
		if ((ret = HookIt(oldfunc,poutold,newfunc)) != FHSuccess)
		{
			fprintf(stderr, "Hook error %d\n", ret);
			exit(1);
		}
	}
	template <typename TName>
	void DoHookInLibAndLibC(void* handle1, void* handle2, typename TName::func_wrapper::ptrFunc replacement_func)
	{
		void* libc = GetFuncAddress(handle1, TName::name);
		_DoHook(libc, (void**)&TName::func_wrapper::old_func, (void*)replacement_func);
		void* libother = GetFuncAddress(handle2, TName::name);
		void* dummy;
		if (libother != libc)
			_DoHook(libother, (void**)&dummy, (void*)replacement_func);
	}

	template <typename TName>
	void DoHook(typename TName::func_wrapper::ptrFunc replacement_func)
	{
		_DoHook(GetFuncAddress(RTLD_NEXT, TName::name), (void**)&TName::func_wrapper::old_func, (void*)replacement_func);
	}

	extern void* GetLibCHandle();
	extern void* GetOtherHandle();
	template <typename TName, typename TName::func_wrapper::ptrFunc replacement_func>
	struct AutoHook
	{
		AutoHook() {
			DoHookInLibAndLibC<TName>(GetLibCHandle(), GetOtherHandle(),replacement_func );
		}
	};

}