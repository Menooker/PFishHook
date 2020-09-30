#include <unistd.h>
#include <stdio.h>
#include <dlfcn.h>
#include <sys/mman.h>
#include "Zydis/Zydis.h"
#include<fcntl.h>
#include <limits.h>
#include "PFishHook.h"
#include <math.h>
#include<sys/syscall.h>


static size_t PageSize2= 0;
static ZydisFormatter formatter;
static ZydisStatus (*ptrParseOperandMem)(const ZydisFormatter* formatter, ZydisString* string,
	const ZydisDecodedInstruction* instruction, const ZydisDecodedOperand* operand, void* userData);

inline size_t divide_and_ceil(size_t x, size_t y)
{
	return 1 + ((x - 1) / y);
}

//align to the floor page
inline void* AlignToPage(void* addr)
{
	return (void*)((uintptr_t)addr & ~(PageSize2 - 1));
}
//align to the ceil page
inline void* AlignToPage_UP(void* addr)
{
	return (void*)(((uintptr_t)addr+PageSize2-1) & ~(PageSize2 - 1));
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
NOTE: use long indirect far jmp
jmp addr64
ff 25 00 00 00 00 addr
size=6+8=14
 */
void GenerateJmpLarge(char* pWriteTo, void* pTarget)
{
	const char jmpl[]="\xff\x25\x00\x00\x00\x00";
	memcpy(pWriteTo,jmpl,6);
	memcpy(pWriteTo+6,&pTarget,8);
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

/*/////////////////////////////////////////////////////
Allocator definitions
*//////////////////////////////////////////////////////


#define mmap(a,b,c,d,e,f) syscall(SYS_mmap,a,b,c,d,e,f)
#define munmap(a,b) syscall(SYS_munmap,a,b)
#define mremap(a,b,c,d) syscall(SYS_mremap,a,b,c,d)

#define MCHUNK_SZ (8*1024*1024)
#define MCHUNK_SZ2 (MCHUNK_SZ-sizeof(void*)-sizeof(size_t))
struct MemChunk{
	struct MemChunk* next;
	size_t allocated;
	char buffer[MCHUNK_SZ2];
	char* alloc(size_t sz){
		char* ret=nullptr;
		if(allocated+sz<=MCHUNK_SZ2){
			ret=buffer+allocated;
			allocated+=sz;
		}
		return ret;
	}
	void init(){
		next=nullptr;
		allocated=0;
		memset(buffer,0xcc,MCHUNK_SZ2);
	}
};
static_assert(sizeof(MemChunk)==MCHUNK_SZ, "sizeof(MemChunk)!=MCHUNK_SZ");
MemChunk* pPool=nullptr;
#define ADDR_OK(x,y) (AddressDiff(x, y) < ((1ULL << 31) - 1))
static char* TryAlloc(size_t sz,void* addr){
	char* ret=nullptr;
	for(MemChunk* now=pPool;now;now=now->next){
		if(addr==nullptr || ADDR_OK(addr,now)){
			ret=now->alloc(sz);
			if(ret) return ret;
		}
	}
	return ret;
}
static MemChunk* TryCreateChunk(void* address){
	/*
	 search a proper place
	 search backwards so that it won't overlap the memory for stack or heap 
	 */
	auto flags=MAP_PRIVATE | MAP_ANONYMOUS ;
	uintptr_t addr=reinterpret_cast<uintptr_t>(address);
	if(addr==0){
		MemChunk* res=(MemChunk*)mmap(addr, MCHUNK_SZ, PROT_READ | PROT_WRITE | PROT_EXEC,flags,-1,0);
		res->init();
		return res;
	}
	if(((uintptr_t)addr >> 32) == 0 && addr!=0) flags|= MAP_32BIT;
	const uintptr_t search_step=(MCHUNK_SZ<<1);
	for(;addr>search_step;addr-=search_step){
		MemChunk* res=(MemChunk*)mmap(addr, MCHUNK_SZ, PROT_READ | PROT_WRITE | PROT_EXEC,flags,-1,0);
		if(ADDR_OK(res,reinterpret_cast<void*>(addr))){
			res->init();
			return res;
		}
		munmap(res,MCHUNK_SZ);
	}
	return nullptr;
}
static char* AllocFunc(size_t sz, void* addr)
{
	char* ret=nullptr;
	ret=TryAlloc(sz,addr);
	if(ret) return ret;
	//create chunk
	MemChunk* res=TryCreateChunk(addr);
	if(!res){
		return nullptr;
	}
	if(!pPool) pPool=res; else pPool->next=res;
	return TryAlloc(sz,addr);
}

#undef ADDR_OK

/*/////////////////////////////////////////////////////
End Allocator definitions
*//////////////////////////////////////////////////////

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

#define FHASSERT(cond,pinst) do{\
	if(!(cond)){\
		fprintf(stderr, "PFishHook is unable to patch this instructions with RIP: %lx\n",\
			*(uint64_t*)pinst);\
		return FHUnrecognizedRIP;\
	}\
}while (0);


static inline HookStatus RangeProtect(void* start,size_t size,int wrable){
	auto start2=AlignToPage(start);
	auto end=AlignToPage_UP((char*)(start)+size);
	if(mprotect(start2,(char*)end-(char*)start2,PROT_READ|PROT_EXEC|(wrable?PROT_WRITE:0))<0)
		return FHMprotectFail;
	return FHSuccess;
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
	}
	ZydisDecoder decoder;
	ZydisDecoderInit(
		&decoder,
		ZYDIS_MACHINE_MODE_LONG_64,
		ZYDIS_ADDRESS_WIDTH_64);
	
	uint64_t instructionPointer = (uint64_t)oldfunc;
	uint8_t* readPointer = (uint8_t*)oldfunc;
	size_t length = 0;

	int patch_jump_bed_size = 0;
	//we first check the head of oldfunc. We use the disassembler to 
	//find the length of each instruction until there is enough space
	//to hold our "jmp" instructions
	hasRIP = false;
	ZydisDecodedInstruction instruction;
	const int jmplen=GetJmpLen(oldfunc,newfunc);
	uint8_t* QWORDPointer=nullptr;
	while (ZYDIS_SUCCESS(ZydisDecoderDecodeBuffer(
		&decoder, readPointer, 128, instructionPointer, &instruction)))
	{
		bool patched = false;
		if (instruction.attributes & ZYDIS_ATTRIB_IS_RELATIVE)
		{
			FHASSERT(instruction.operandCount >= 1, instruction.instrAddress);
			for (int i = 0; i < instruction.operandCount; i++) //for all operands, check if it is RIP-relative
			{
				auto operand = &instruction.operands[i];
				if (operand->type == ZYDIS_OPERAND_TYPE_MEMORY && operand->mem.disp.hasDisplacement)
				{
					FHASSERT(operand->mem.base != ZYDIS_REGISTER_EIP, instruction.instrAddress);
					if (operand->mem.base == ZYDIS_REGISTER_RIP)
					{
						FHASSERT(instruction.raw.disp.size == 32, instruction.instrAddress);
						patched = true;
						/*
						NOTE: We might meet jmp QWORD PTR [rip].While this instr reads mem at rip+6 (we will modify this address),
						we should copy QWORD rip+6 to shadow function
						 */
						auto pOffset=(int32_t*)(readPointer + instruction.raw.disp.offset);
						auto word_offset=(readPointer + *pOffset) - (uint8_t*)oldfunc+instruction.length;
						//printf("off %d\n",*pOffset);
						//jmpq QWORD ptr [rip+0] (6) QWORD (8)
						if(word_offset<jmplen && instruction.mnemonic>=ZYDIS_MNEMONIC_JB && instruction.mnemonic<=ZYDIS_MNEMONIC_JZ){
							//Uhh We should copy this word to shadow function
							//In most cases,This only happen when a function is hooked
							FHASSERT(QWORDPointer==nullptr,instruction.instrAddress);
							QWORDPointer=readPointer+(*pOffset)+instruction.length;
						}else{
						if (InsertPatchPoint(PatchInfoPool, num_patch_points, FHPatchLoad32, (readPointer + instruction.raw.disp.offset) - (uint8_t*)oldfunc))
							return FHTooManyPatches;
						}
					}
				}
				else if (operand->type == ZYDIS_OPERAND_TYPE_IMMEDIATE)
				{
					if (operand->imm.isSigned && operand->imm.isRelative)
					{
						if (instruction.raw.imm[0].size == 8)
						{
							patched = true;
							if (InsertPatchPoint(PatchInfoPool, num_patch_points, FHPatchJump8,
								(readPointer + instruction.raw.imm[0].offset) - (uint8_t*)oldfunc))
								return FHTooManyPatches;
							//if there is a jmp instruction, we need one more "jmp" in
							//our jump space to patch it, so add alloc_size with GetJmpLen()
							patch_jump_bed_size += GetJmpLenLarge();
						}
						else if (instruction.raw.imm[0].size == 32)
						{
							patched = true;
							if (InsertPatchPoint(PatchInfoPool, num_patch_points, FHPatchLoad32,
								(readPointer + instruction.raw.imm[0].offset) - (uint8_t*)oldfunc))
								return FHTooManyPatches;
						}
						else
						{
							FHASSERT(0, instruction.instrAddress);
						}
					}
				}
			}	
			FHASSERT(patched, instruction.instrAddress);
		}
		if(readPointer+instruction.length==QWORDPointer){
			instruction.length+=8;
			//skip the QWORD
		}
		readPointer += instruction.length;
		length += instruction.length;
		if (length >= jmplen)
			break;
		instructionPointer += instruction.length;
	}
	if (length < jmplen)
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
			//if there is a 32-bit relative instr
			int32_t offset; offset = *(int32_t*)((unsigned char*)oldfunc + PatchInfoPool[i].patch_addr_offset);
			//calculate the new relative offset
			int64_t delta; delta = (int64_t)offset - ((char*)outfunc - (char*)oldfunc);
			if (delta > INT_MAX || delta < INT_MIN)
			{
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
	if(RangeProtect(oldfunc,length,1)!=FHSuccess) return FHMprotectFail;
	//replace the head of oldfunc with newfunc
	GenerateJmp((char*)oldfunc, newfunc);
	//fill the gap with "int 3"
	memset((char*)oldfunc+ GetJmpLen((char*)oldfunc, newfunc), 0xcc, length- GetJmpLen((char*)oldfunc, newfunc));
	//restore the protection
	if(RangeProtect(oldfunc,length,0)!=FHSuccess) return FHMprotectFail;
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
	if(RangeProtect(oldfunc,length,1)!=FHSuccess) return FHMprotectFail;
	memcpy(oldfunc,func,length);
	if(RangeProtect(oldfunc,length,0)!=FHSuccess) return FHMprotectFail;
	return FHSuccess;
}
