#include <unistd.h>
#include <stdio.h>
#include <dlfcn.h>
#include <sys/mman.h>
#include "Zydis/Zydis.h"
//#include "util.h"
#include<fcntl.h>
#include <limits.h>
#include "PFishHook.h"


static size_t PageSize2= 0;

inline size_t divide_and_ceil(size_t x, size_t y)
{
	return 1 + ((x - 1) / y);
}

inline void* AlignToPage(void* addr)
{
	return (void*)((uintptr_t)addr & ~(PageSize2 - 1));
}

/*unsigned char hook_head[] = {
	0x48,0xbb,0x35,0x08,0x40,0x00,0x00,0x00,0x00,0x00,//   mov rbx, 0x0000000000400835
	0xff, 0xe3 //jmp rbx
};*/

/*
Generate "Far jmp" in x64. Generated code are :
	push (lower 32 bits of the target)
	mov dword ptr ss:[rsp+4],(higher 32 bits of the target)
	ret
Thanks for "yes2". Reference http://blog.csdn.net/yes2/article/details/50580384
Params:
	pWriteTo - The address to store the generated code. Use GetJmpLen()
		to get the length of instructions to be gengerated
	pTarget - The target address to jmp to
*/
void GenerateJmp(char* pWriteTo, void* pTarget)
{
	*pWriteTo = 0x68;
	pWriteTo += 1;
	*(uint32_t*)pWriteTo = uint32_t((uintptr_t)pTarget & 0xffffffff);
	pWriteTo += 4;
	*(uint32_t*)pWriteTo = 0x042444c7;
	pWriteTo += 4;
	*(uint32_t*)pWriteTo = uint32_t((uintptr_t)pTarget >> 32);
	pWriteTo += 4;
	*pWriteTo = 0xc3;
}
/*
Get the length of instructions to be gengerated by GenerateJmp()
*/
int GetJmpLen()
{
	return 14;
}

#define ALIGN_SIZE 8
#define ALLOC_SIZE (4096*2)
//#define mmap_bypass mmap

/*
Alloc the "jump space" for old function head
*/
char* AllocFunc(size_t sz)
{
	static char* buf = (char*)mmap(nullptr, ALLOC_SIZE, PROT_READ | PROT_WRITE | PROT_EXEC, MAP_PRIVATE| MAP_ANONYMOUS, -1, 0);
	static size_t cur_len=0;
	size_t alloc_sz = divide_and_ceil(sz, ALIGN_SIZE)*ALIGN_SIZE;

	//fprintf(stderr, "Alloc buf  %p, curlen=%d, sz=%d\n", buf, cur_len, alloc_sz);
	if (cur_len+ alloc_sz >= ALLOC_SIZE)
		return nullptr;
	char* ret = buf + cur_len;
	cur_len += alloc_sz;
	return ret;
}



/*
Do Hook. It will replace the head of the function "oldfunc" with a "jmp" to the function "newfunc",
and copy the the head of the function "oldfunc" to newly alloacted space ("jump space"), returning the pointer to
the "jump space" with "poutold". If success, return "FHSuccess"
*/
HookStatus HookIt(void* oldfunc, void** poutold, void* newfunc)
{
	if (PageSize2 == 0)
		PageSize2 = sysconf(_SC_PAGESIZE);
	ZydisDecoder decoder;
	ZydisDecoderInit(
		&decoder,
		ZYDIS_MACHINE_MODE_LONG_64,
		ZYDIS_ADDRESS_WIDTH_64);
	ZydisFormatter formatter;
	ZydisFormatterInit(&formatter, ZYDIS_FORMATTER_STYLE_INTEL);
	uint64_t instructionPointer = (uint64_t)oldfunc;
	uint8_t* readPointer = (uint8_t*)oldfunc;
	size_t length = 0;
	const unsigned char patch_target[] = { 0x83, 0x3d }; //check cmp relative
	const unsigned char patch_target_jne[] = { 0x75 , 0x77 }; //check jne/ja relative
	unsigned char* patch_addr=nullptr;
	unsigned char* patch_addr_jne = nullptr;

	//we first check the head of oldfunc. We use the disassembler to 
	//find the length of each instruction until there is enough space
	//to hold our "jmp" instructions
	ZydisDecodedInstruction instruction;
	while (ZYDIS_SUCCESS(ZydisDecoderDecodeBuffer(
		&decoder, readPointer, 128, instructionPointer, &instruction)))
	{
		//if it is a cmp relative instr
		if (!memcmp(readPointer, patch_target, sizeof(patch_target)))
		{
			patch_addr = readPointer;
		}
		//if it is a jne relative instr
		for(int i=0;i<sizeof(patch_target_jne);i++)
		{
			if (*readPointer== patch_target_jne[i])
			{
				patch_addr_jne = readPointer;
				break;
			}
		}
		readPointer += instruction.length;
		length += instruction.length;
		if (length >= GetJmpLen())
			break;
		instructionPointer += instruction.length;
	}
	if (length < GetJmpLen())
		return FHDecodeFailed;

	//now "length" is the length of instructions in oldfunc to be replaced
	/*
	The jump space is composed of
		- oldfunc's replaced function head (with length "length")
		- the "jmp" instruction jumping to the body of oldfunc
	Also, we need to remember the alloc_size 
	*/
	size_t alloc_size = length + GetJmpLen() + sizeof(size_t);
	
	//if there is a jne instruction, we need one more "jmp" in
	//our jump space to patch it, so add alloc_size with GetJmpLen()
	if (patch_addr_jne)
		alloc_size += GetJmpLen();
	char* outfunc = AllocFunc(alloc_size);
	if (!outfunc)
		return FHAllocFailed;

	//record the length of replaced instructions
	*(size_t*)outfunc = length;
	outfunc += sizeof(size_t);

	//copy oldfunc's first several instructions to the jump space
	memcpy(outfunc, oldfunc, length);
	//generate a "jmp" back to oldfunc's body
	GenerateJmp(outfunc + length,(char*)oldfunc+length);
	
	if (patch_addr)
	{
		//if there is a cmp relative instr
		int32_t offset = *(int32_t*)(patch_addr + 2);
		//calculate the new relative offset
		int64_t delta = (int64_t)offset - ((char*)outfunc - (char*)oldfunc);
		if (delta > INT_MAX || delta < INT_MIN)
		{
			//if the relative offset is too large to be held in 32 bits
			return FHPatchFailed;
		}
		int32_t* patch_point = (int32_t*)(outfunc + (patch_addr + 2 - (unsigned char*)oldfunc));
		*patch_point = delta;
	}
	if (patch_addr_jne)
	{
		//if there is a jne "near" relative instr, the offset is too small to
		//jump from jump space to oldfun's body. So we first "jne near" to a place
		//in jump space, and then use our "far jmp" to jump to the target
		char* patch_instruction = (char*)(outfunc + (patch_addr_jne  - (unsigned char*)oldfunc));
		char delta = outfunc + length + GetJmpLen() - (patch_instruction + 2);
		patch_instruction[1] = delta;
		uintptr_t target = (uintptr_t) patch_addr_jne + 2 + patch_addr_jne[1];
		char* jmp_bed = outfunc + length + GetJmpLen();
		GenerateJmp(jmp_bed, (void*)target);
	}
	*poutold = (void*)outfunc;
	//Let the pages of oldfunc writable
	for (uintptr_t start = (uintptr_t)AlignToPage(oldfunc); start <= (uintptr_t)AlignToPage((char*)oldfunc + length - 1); start += PageSize2)
	{
		if (mprotect(AlignToPage(oldfunc), PageSize2, PROT_READ | PROT_EXEC | PROT_WRITE)<0)
			return FHMprotectFail;
	}

	//replace the head of oldfunc with newfunc
	GenerateJmp((char*)oldfunc, newfunc);
	//fill the gap with "int 3"
	memset((char*)oldfunc+ GetJmpLen(), 0xcc, length- GetJmpLen());
	//restore the protection
	for (uintptr_t start = (uintptr_t)AlignToPage(oldfunc); start <= (uintptr_t)AlignToPage((char*)oldfunc + length - 1); start += PageSize2)
	{
		if (mprotect(AlignToPage(oldfunc), PageSize2, PROT_READ | PROT_EXEC )<0)
			return FHMprotectFail;
	}
	return FHSuccess;
}

HookStatus UnHook(void* oldfunc, void* func)
{
	//todo : reset patch
	size_t length = *((size_t*)func - 1);
	for (uintptr_t start = (uintptr_t)AlignToPage(oldfunc); start <= (uintptr_t)AlignToPage((char*)oldfunc + length - 1); start += PageSize2)
	{
		if (mprotect(AlignToPage(oldfunc), PageSize2, PROT_READ | PROT_EXEC | PROT_WRITE)<0)
			return FHMprotectFail;
	}

	memcpy(oldfunc, func, length);

	for (uintptr_t start = (uintptr_t)AlignToPage(oldfunc); start <= (uintptr_t)AlignToPage((char*)oldfunc + length - 1); start += PageSize2)
	{
		if (mprotect(AlignToPage(oldfunc), PageSize2, PROT_READ | PROT_EXEC)<0)
			return FHMprotectFail;
	}
	return FHSuccess;
}

/*
int hehe(int a, char* b, size_t c)
{
	printf("a=%d b=%s c=%d", a, b, c);
	return a;
}

typedef ssize_t(*ptrread)(int fd, void *buf, size_t nbytes);
ptrread oldread;
extern "C" ssize_t myread(int fd, void *buf, size_t nbytes)
{
	fprintf(stderr, "read\n");
	ssize_t ret= oldread(fd,buf,nbytes);
	fprintf(stderr, "read ret%d\n",ret);
	return ret;
	//return CallHooked(Name_read(),my_read, ssize_t(), fd, buf, nbytes);
}

void readwrite()
{
	int fd, size;
	char s[] = "Linux Programmer!\n", buffer[80];
	fd = open("/tmp/temp", O_WRONLY | O_CREAT);
	write(fd, s, sizeof(s));
	close(fd);
	fd = open("/tmp/temp", O_RDONLY);
	size = read(fd, buffer, sizeof(buffer));
	close(fd);
	printf("%s", buffer);
}
int main()
{

	//printf("addr %p\n", dlsym(RTLD_NEXT, "read"));
	
	printf("Hook %d\n",HookIt((void*)hehe, (void**)&oldread, (void*)myread));
	//readwrite();
	hehe(12, "ff", 32);
	printf("Done");
	fflush(stdout);
	//UnHook(dlsym(RTLD_NEXT, "read"), (void*)oldread);
	return 0;
}*/