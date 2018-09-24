#include <unistd.h>
#include <stdio.h>
#include <dlfcn.h>
#include <sys/mman.h>
#include "Zydis/Zydis.h"
//#include "util.h"
#include<fcntl.h>
#include <limits.h>
#include "PFishHook.h"
#include <math.h>
#include<sys/syscall.h>
/*struct ldtt {
               unsigned int  entry_number;
               unsigned long base_addr;
               unsigned int  limit;
               unsigned int  seg_32bit:1;
               unsigned int  contents:2;
               unsigned int  read_exec_only:1;
               unsigned int  limit_in_pages:1;
               unsigned int  seg_not_present:1;
               unsigned int  useable:1;
           };*/
static void* availbuf=0; //the address of the start of the code/text segment
static size_t PageSize2= 0;
static ZydisFormatter formatter;
static ZydisStatus (*ptrParseOperandMem)(const ZydisFormatter* formatter, ZydisString* string,
	const ZydisDecodedInstruction* instruction, const ZydisDecodedOperand* operand, void* userData);

inline size_t divide_and_ceil(size_t x, size_t y)
{
	return 1 + ((x - 1) / y);
}

inline void* AlignToPage(void* addr)
{
	return (void*)((uintptr_t)addr & ~(PageSize2 - 1));
}

inline size_t AddressDiff(void* a, void* b)
{
	uintptr_t chunkaddr = (uintptr_t)a;
	uintptr_t laddr = (uintptr_t)b;
	size_t diff;
	if (chunkaddr > laddr)
		diff = chunkaddr - laddr;
	else
		diff = laddr - chunkaddr;
	return diff;
}

static bool hasRIP = false;
/*
The function to check if there is RIP-relative memory loads in the instruction
*/
static ZydisStatus ParseOperandMem(const ZydisFormatter* formatter, ZydisString* string,
	const ZydisDecodedInstruction* instruction, const ZydisDecodedOperand* operand, void* userData)
{
	if (operand->mem.disp.hasDisplacement && (
		(operand->mem.base == ZYDIS_REGISTER_EIP) ||
		(operand->mem.base == ZYDIS_REGISTER_RIP)) &&
		(operand->mem.index == ZYDIS_REGISTER_NONE) && (operand->mem.scale == 0))
	{
		hasRIP = true;
	}
	return ptrParseOperandMem(formatter, string, instruction, operand, userData);
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

void GenerateJmpLarge(char* pWriteTo, void* pTarget)
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
void GenerateJmp(char* pWriteTo, void* pTarget)
{
	if (AddressDiff(pWriteTo+5, pTarget) < ((1ULL << 31) - 1))
	{
		*pWriteTo = 0xe9; //if displacement is small,use jmp
		pWriteTo += 1;
		*(uint32_t*)pWriteTo = uint32_t((char*)pTarget - (pWriteTo+4));
		return;
	}
	GenerateJmpLarge(pWriteTo, pTarget);
}
/*
Get the length of instructions to be gengerated by GenerateJmp()
*/
int GetJmpLen(void* pWriteTo, void* pTarget)
{
	if (AddressDiff((char*)pWriteTo + 6, pTarget) < ((1ULL << 31) - 1))
	{
		return 5;
	}
	return 14;
}

/*
Get the length of instructions to be gengerated by GenerateJmp()
*/
int GetJmpLenLarge()
{
	return 14;
}

#define ALIGN_SIZE 8
#define ALLOC_SIZE (4096*2)
struct MemChunk
{
	size_t allocated;
	MemChunk* next;
	char buffer[0];
};
#define ALLOC_AVAILABLE (ALLOC_SIZE-sizeof(MemChunk))
//#define mmap_bypass mmap
#define mmap(a,b,c,d,e,f) syscall(SYS_mmap,a,b,c,d,e,f)



static MemChunk * FuncBuffer = nullptr;
/*
Alloc the "jump space" for old function head
*/
static char* AllocFunc(size_t sz,void* addr)
{
	
	//static size_t cur_len=0;
	MemChunk *chunk = (MemChunk*)FuncBuffer;
	char* ret=nullptr;
	if (addr)
	{
		//if specified an address
		//first find a memory chunk near to the address
		//if not found, allocate one
		MemChunk *cur = chunk;
		bool found = false;
		while (true)
		{
			if (AddressDiff(addr, cur) < ((1ULL << 31) - 1)) //if the difference is < 2g
			{
				chunk = cur;
				found = true;
				break;
			}
			if (cur->next) //we still need to find the tail of the list
				cur = cur->next;
			else
				break;
		}
		if (!found)
		{
			if ((uintptr_t)addr >> 32 == 0) //if the suggested addr is in lower 4g address
			{
				chunk = (MemChunk*)mmap(addr, ALLOC_SIZE, PROT_READ | PROT_WRITE | PROT_EXEC, MAP_PRIVATE | MAP_ANONYMOUS| MAP_32BIT, -1, 0);
			}
			else
			{
				chunk = (MemChunk*)mmap(addr, ALLOC_SIZE, PROT_READ | PROT_WRITE | PROT_EXEC, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
				if (chunk!=MAP_FAILED && availbuf!=nullptr 
					&& AddressDiff(chunk, addr) >= ((1ULL << 31) - 1)){ 
					//if we used the hint, but the address difference is still too large, try to mmap an address before the ".text" segment
					munmap(chunk,ALLOC_SIZE);
					chunk=(MemChunk*)mmap(availbuf, ALLOC_SIZE, PROT_READ | PROT_WRITE | PROT_EXEC, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
					availbuf=(void*)chunk;
				}
			}
			if(chunk==MAP_FAILED)
				return nullptr;
			chunk->next = nullptr;
			chunk->allocated = 0;
			cur->next = chunk; //append the new chunk to the tail of the list
			if (AddressDiff(chunk, addr) >= ((1ULL << 31) - 1)) //if still cannot find
				return nullptr;
		}
	}
	size_t alloc_sz = divide_and_ceil(sz, ALIGN_SIZE)*ALIGN_SIZE;

	//fprintf(stderr, "Alloc buf  %p, curlen=%d, sz=%d\n", buf, cur_len, alloc_sz);
	if (chunk->allocated + alloc_sz >= ALLOC_SIZE)
		return nullptr;
	ret = chunk->buffer + chunk->allocated;
	chunk->allocated += alloc_sz;
	memset(ret, 0xcc, alloc_sz);

	return ret;
}

void* GetELFAddr(){
	char buf[256];
	int fd=syscall(SYS_open,"/proc/self/maps",O_RDONLY);
	syscall(SYS_read,fd,buf,256);
	syscall(SYS_close,fd);
	void* ret;
	sscanf(buf,"%p",&ret);
	return ret;
}

enum PatchType
{
	FHPatchLoad32,
	FHPatchJump8,
};
struct PatchInfo
{
	PatchType type;
	int patch_addr_offset; //the offset of the address of the target to patch 
};
#define MAX_PATCH_POINTS 10


inline bool InsertPatchPoint(PatchInfo* pool, int& num_patch_points, PatchType type, int offset)
{
	//alloacte a patch point info
	if (num_patch_points >= MAX_PATCH_POINTS)
		return true;
	PatchInfo* pinfo = pool + num_patch_points;
	num_patch_points++;

	pinfo->type = type;// FHPatchLoad32;
	pinfo->patch_addr_offset = offset;//(readPointer + len) - (uint8_t*)oldfunc;
	return false;
}
/*
Do Hook. It will replace the head of the function "oldfunc" with a "jmp" to the function "newfunc",
and copy the the head of the function "oldfunc" to newly alloacted space ("jump space"), returning the pointer to
the "jump space" with "poutold". If success, return "FHSuccess"
*/
HookStatus HookItSafe(void* oldfunc, void** poutold, void* newfunc, int need_checking,void* suggested_address)
{
	int num_patch_points = 0;
	static PatchInfo PatchInfoPool[MAX_PATCH_POINTS];

	if (PageSize2 == 0)
	{
		PageSize2 = sysconf(_SC_PAGESIZE);
		ZydisFormatterInit(&formatter, ZYDIS_FORMATTER_STYLE_INTEL);
		ptrParseOperandMem = ParseOperandMem;
		ZydisFormatterSetHook(&formatter, ZYDIS_FORMATTER_HOOK_FORMAT_OPERAND_MEM, (const void**)&ptrParseOperandMem);
		FuncBuffer= (MemChunk*)mmap(nullptr, ALLOC_SIZE, PROT_READ | PROT_WRITE | PROT_EXEC, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
		FuncBuffer->next = nullptr;
		FuncBuffer->allocated = 0;
		uintptr_t baseaddr = (uintptr_t)GetELFAddr();
		if(baseaddr>>32!=0)
			availbuf=(void*)(baseaddr-(uintptr_t)0x20000000); //512MB
	}
	ZydisDecoder decoder;
	ZydisDecoderInit(
		&decoder,
		ZYDIS_MACHINE_MODE_LONG_64,
		ZYDIS_ADDRESS_WIDTH_64);
	
	uint64_t instructionPointer = (uint64_t)oldfunc;
	uint8_t* readPointer = (uint8_t*)oldfunc;
	size_t length = 0;

	const unsigned char patch_target_32_load[][5] = { //instructions with 32-bit relative offset memory load
		{0x83, 0x3d}, //cmp relative
		{0xe9}, //jmpq
	}; 
	const unsigned char patch_target_32_load_instr_len[]
	{
		2, //cmp relative
		1, //jmpq
	};
	const int patch_target_32_load_len = sizeof(patch_target_32_load) / sizeof(patch_target_32_load[0]);

	const unsigned char patch_target_8_jmp[] = { //8-bit relative jump instructions 
		0xe3,//JCXZ
		0xeb,//jmp
	}; 
	const int patch_target_8_jmp_len = sizeof(patch_target_8_jmp) / sizeof(patch_target_8_jmp[0]);

	int patch_jump_bed_size = 0;
	//unsigned char* patch_addr=nullptr;
	//unsigned char* patch_addr_jne = nullptr;

	//we first check the head of oldfunc. We use the disassembler to 
	//find the length of each instruction until there is enough space
	//to hold our "jmp" instructions
	hasRIP = false;
	ZydisDecodedInstruction instruction;
	while (ZYDIS_SUCCESS(ZydisDecoderDecodeBuffer(
		&decoder, readPointer, 128, instructionPointer, &instruction)))
	{
		bool processed = false;
		//if it is a cmp relative instr
		for (int i = 0; i < patch_target_32_load_len; i++)
		{
			int len = patch_target_32_load_instr_len[i];
			if (!memcmp(readPointer, patch_target_32_load[i],len))
			{
				//fprintf(stderr, "PATCH %x\n", patch_target_32_load[i][0]);
				if(InsertPatchPoint(PatchInfoPool, num_patch_points, FHPatchLoad32, (readPointer + len) - (uint8_t*)oldfunc))
					return FHTooManyPatches;
				processed = true;
				break;
			}
		}

		//if it is a jne relative instr
		if (!processed && *readPointer >= 0x70 && *readPointer <= 0x7f)
		{
			if (InsertPatchPoint(PatchInfoPool, num_patch_points, FHPatchJump8, (readPointer + 1) - (uint8_t*)oldfunc))
				return FHTooManyPatches;
			//if there is a jne instruction, we need one more "jmp" in
			//our jump space to patch it, so add alloc_size with GetJmpLen()
			patch_jump_bed_size += GetJmpLenLarge();
			processed = true;
		}
		else if (!processed)
		{
			for (int i = 0; i<patch_target_8_jmp_len; i++)
			{
				if (*readPointer == patch_target_8_jmp[i])
				{
					if (InsertPatchPoint(PatchInfoPool, num_patch_points, FHPatchJump8, (readPointer + 1) - (uint8_t*)oldfunc))
						return FHTooManyPatches;
					//if there is a jne instruction, we need one more "jmp" in
					//our jump space to patch it, so add alloc_size with GetJmpLen()
					patch_jump_bed_size += GetJmpLenLarge();
					processed = true;
					break;
				}
			}
		}
		if(need_checking && !processed)
		{
			char buffer[256];
			ZydisFormatterFormatInstruction(
				&formatter, &instruction, buffer, sizeof(buffer));
			if (hasRIP)
			{
				fprintf(stderr, "PFishHook is unable to patch this instruction with RIP: %s\nPlease report an issue at github.com/Menooker/PFishHook.\n",
					buffer);
				return FHUnrecognizedRIP;
			}
		}
		readPointer += instruction.length;
		length += instruction.length;
		if (length >= GetJmpLen(oldfunc,newfunc))
			break;
		instructionPointer += instruction.length;
	}
	if (length < GetJmpLen(oldfunc, newfunc))
		return FHDecodeFailed;

	//now "length" is the length of instructions in oldfunc to be replaced
	/*
	The jump space is composed of
		- oldfunc's replaced function head (with length "length")
		- the "jmp" instruction jumping to the body of oldfunc
	Also, we need to remember the alloc_size 
	*/
	size_t alloc_size = length + GetJmpLenLarge() + sizeof(size_t) + patch_jump_bed_size;

	char* outfunc = AllocFunc(alloc_size, suggested_address);
	if (!outfunc)
		return FHAllocFailed;

	//record the length of replaced instructions
	*(size_t*)outfunc = length;
	outfunc += sizeof(size_t);

	//copy oldfunc's first several instructions to the jump space
	memcpy(outfunc, oldfunc, length);
	//generate a "jmp" back to oldfunc's body
	GenerateJmpLarge(outfunc + length,(char*)oldfunc+length);

	//now get each PatchInfo and do patching in the copied function head
	int jump_bed_num = 0;
	for (int i = 0; i < num_patch_points; i++)
	{
		switch (PatchInfoPool[i].type)
		{
		case FHPatchLoad32:
			//if there is a cmp relative instr
			int32_t offset; offset = *(int32_t*)((unsigned char*)oldfunc + PatchInfoPool[i].patch_addr_offset);
			//calculate the new relative offset
			int64_t delta; delta = (int64_t)offset - ((char*)outfunc - (char*)oldfunc);
			if (delta > INT_MAX || delta < INT_MIN)
			{
				//fprintf(stderr, "Too large %p,%d\n", outfunc, oldfunc);
				//if the relative offset is too large to be held in 32 bits
				//we retry with a suggested address. If there is already a 
				//suggested address, return failure.
				if(suggested_address)
					return FHPatchFailed;
				return HookItSafe(oldfunc, poutold, newfunc, need_checking, oldfunc);
			}
			//the patch point in copied function
			int32_t* patch_point;patch_point = (int32_t*)(outfunc + PatchInfoPool[i].patch_addr_offset);
			*patch_point = delta;
			break;
		case FHPatchJump8:
			//if there is a jne "near" relative instr, the offset is too small to
			//jump from jump space to oldfun's body. So we first "jne near" to a place
			//in jump space, and then use our "far jmp" to jump to the target
			unsigned char* patch_addr_jne; // the address of the instruction in old function
			patch_addr_jne = (unsigned char* )oldfunc + PatchInfoPool[i].patch_addr_offset - 1;
			//the address of the instruction in new function
			char* patch_instruction; patch_instruction = (char*)(outfunc + PatchInfoPool[i].patch_addr_offset - 1);
			uintptr_t target; target = (uintptr_t)patch_addr_jne + 2 + patch_addr_jne[1];

			//check if the jump target is within the copied part of the function. If so, no need to patch
			int jump_target_offset; jump_target_offset = (char*)target - (char*)oldfunc;
			if (jump_target_offset >= 0 && jump_target_offset < length)
				continue;
			/*where should we jump to now?
			remember the layout of the jump space:
			[copied function head]                     ----  length= "length"
			[a "jmp" instruction to original function] ----  length= "GetJmpLen()"
			[several "jmp" instructions to handle near jmp(s)]
			*/
			int delta8;
			delta8 = outfunc + length + GetJmpLenLarge() + jump_bed_num * GetJmpLenLarge() - (patch_instruction + 2);
			if (delta8 > 127 || delta8 < -128)
			{
				//fprintf(stderr, "Too large %p,%p\n", outfunc + length + GetJmpLen() + jump_bed_num * GetJmpLen(), patch_instruction + 2);
				return FHPatchFailed;
			}
			patch_instruction[1] = delta8;
			
			char* jmp_bed = outfunc + length + GetJmpLenLarge()+ jump_bed_num * GetJmpLenLarge();
			GenerateJmpLarge(jmp_bed, (void*)target);
			jump_bed_num++;
		}
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
	memset((char*)oldfunc+ GetJmpLen((char*)oldfunc, newfunc), 0xcc, length- GetJmpLen((char*)oldfunc, newfunc));
	//restore the protection
	for (uintptr_t start = (uintptr_t)AlignToPage(oldfunc); start <= (uintptr_t)AlignToPage((char*)oldfunc + length - 1); start += PageSize2)
	{
		if (mprotect(AlignToPage(oldfunc), PageSize2, PROT_READ | PROT_EXEC )<0)
			return FHMprotectFail;
	}
	return FHSuccess;
}


HookStatus HookIt(void* oldfunc, void** poutold, void* newfunc)
{
	return HookItSafe(oldfunc, poutold, newfunc, 1,nullptr);
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
