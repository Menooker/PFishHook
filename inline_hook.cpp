#include <cstddef>
#include <cstdint>
#include <string.h>
#include <unistd.h>
#include <stdio.h>
#include <dlfcn.h>
#include <sys/mman.h>
#include "Zycore/String.h"
#include "Zydis/Zydis.h"
#include <fcntl.h>
#include <limits.h>
#include "PFishHook.h"
#include <math.h>
#include <sys/syscall.h>

static size_t PageSize= 0;
static ZydisFormatter formatter;
static ZyanStatus (*ptrParseOperandMem)(const ZydisFormatter* formatter, ZyanString* string,
	const ZydisDecodedInstruction* instruction, const ZydisDecodedOperand* operand, void* userData);

inline size_t divide_and_ceil(size_t x, size_t y)
{
	return 1 + ((x - 1) / y);
}

//align to the floor page
inline void* AlignToPage(void* addr)
{
	return (void*)((uintptr_t)addr & ~(PageSize - 1));
}
//align to the ceil page
inline void* AlignToPage_UP(void* addr)
{
	return (void*)(((uintptr_t)addr+PageSize-1) & ~(PageSize - 1));
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
static ZyanStatus ParseOperandMem(const ZydisFormatter* formatter, ZyanString* string,
	const ZydisDecodedInstruction* instruction, const ZydisDecodedOperand* operand, void* userData)
{
	if (operand->mem.disp.has_displacement && (
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
int GetJmpLenLarge()
{
	return 14;
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
	return GetJmpLenLarge();
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

#define FHASSERT(cond,pinst) do{\
	if(!(cond)){\
		fprintf(stderr, "PFishHook is unable to patch this instructions with RIP: %lx\n",\
			*(uint64_t*)pinst);\
		return FHPatchFailed;\
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
/*
                                        newfunc          
                                        ^                
                                        |  jmp           
                                        |                
                                      +-+------+ +------+
                      oldfunc  ---->  | header | | body |
                                      +--------+ +------+
                                      |        |  ^      
                                      |        |  |      
                                      |        |  |      
+-----+------------+-----+------------+--------+  |      
| len | new header | jmp | backup len | backup |  |      
+--1--+------------+-14--+-----1------+--------+  |      
        ^             |                           |      
        |             +---------------------------+      
        |                                                
        poutold                                          
 */
	if (oldfunc == nullptr) {
		return FHDecodeFailed;
	}
	if (PageSize == 0)
	{
		PageSize = sysconf(_SC_PAGESIZE);
		ZydisFormatterInit(&formatter, ZYDIS_FORMATTER_STYLE_INTEL);
		ptrParseOperandMem = ParseOperandMem;
		ZydisFormatterSetHook(&formatter, ZYDIS_FORMATTER_FUNC_FORMAT_OPERAND_MEM,
			(const void**)&ptrParseOperandMem);
	}
	ZydisDecoder decoder;
	ZydisDecoderInit(
		&decoder,
		ZYDIS_MACHINE_MODE_LONG_64,
		ZYDIS_STACK_WIDTH_64);
	
	uint64_t instructionPointer = (uint64_t)oldfunc;
	uint8_t* readPointer = (uint8_t*)oldfunc;
	char length = 0;

	//we first check the head of oldfunc. We use the disassembler to 
	//find the length of each instruction until there is enough space
	//to hold our "jmp" instructions
	//FIXME:now, we dont have effective methods to get the length of oldfunc.
	//from symbol-table?from debug info?
	hasRIP = false;
	ZydisDecodedInstruction instruction;
	const int jmplen=GetJmpLen(oldfunc,newfunc);
	ZydisDecodedOperand operands[ZYDIS_MAX_OPERAND_COUNT];
	memset(operands, 0, sizeof(operands));
	char* outfunc = AllocFunc(128, nullptr);
	if (!outfunc)
		return FHAllocFailed;
	char* changeHeader = outfunc + 1;
	while (ZYAN_SUCCESS(ZydisDecoderDecodeFull(
		&decoder, readPointer, 128, &instruction, operands)))
	{
		if (instruction.attributes & ZYDIS_ATTRIB_IS_RELATIVE)
		{
			bool farJump = false;
			ZydisEncoderRequest req;
			memset(&req, 0, sizeof(req));
			if(!ZYAN_SUCCESS(ZydisEncoderDecodedInstructionToEncoderRequest(&instruction, operands,
				instruction.operand_count_visible, &req)))
			{
				return FHEncodeFailed;
			}
			FHASSERT(instruction.operand_count_visible >= 1, instructionPointer);
			for (int i = 0; i < instruction.operand_count_visible; i++) //for all operands, check if it is RIP-relative
			{
				auto operand = &operands[i];
				if (operand->type == ZYDIS_OPERAND_TYPE_MEMORY && operand->mem.disp.has_displacement)
				{
					FHASSERT(operand->mem.base != ZYDIS_REGISTER_EIP, instructionPointer);
					if (operand->mem.base == ZYDIS_REGISTER_RIP)
					{
						req.operands[i].mem.displacement = operand->mem.disp.value - (uint64_t)changeHeader + instructionPointer;
						FHASSERT(instruction.raw.disp.size == 32, instructionPointer);
						/*
						NOTE: We might meet jmp QWORD PTR [rip].While this instr reads mem at rip+6 (we will modify this address),
						we should copy QWORD rip+6 to shadow function
						 */
						auto pOffset=(int32_t*)(readPointer + instruction.raw.disp.offset);
						auto word_offset=(readPointer + *pOffset) - (uint8_t*)oldfunc+instruction.length;
						//jmpq QWORD ptr [rip+0] (6) QWORD (8)
						if(word_offset<jmplen && instruction.mnemonic>=ZYDIS_MNEMONIC_JB && instruction.mnemonic<=ZYDIS_MNEMONIC_JZ){
							//Uhh We should copy this word to shadow function
							//In most cases,This only happen when a function is hooked
							farJump = true;
						}
					}
				}
				else if (operand->type == ZYDIS_OPERAND_TYPE_IMMEDIATE)
				{
					if (operand->imm.is_signed && operand->imm.is_relative)
					{
						// the jmp range in the oldfunc usually small. when we copy instruction to jump chunk, we need a far jmp
						// if the jump range is larger than 32-bit, encode func will return FHEncodeFailed
						if (req.mnemonic != ZYDIS_MNEMONIC_CALL) {// jmp rel32
							req.branch_width = ZYDIS_BRANCH_WIDTH_32;
							req.branch_type = ZYDIS_BRANCH_TYPE_NEAR;
						}
						req.operands[i].imm.s = operand->imm.value.s - (uint64_t)changeHeader + instructionPointer;
					}
				}
			}
			ZyanU8 encoded_instruction[ZYDIS_MAX_INSTRUCTION_LENGTH];
			ZyanUSize encoded_length = sizeof(encoded_instruction);
			memset(encoded_instruction, 0, sizeof(encoded_instruction));
			if(!ZYAN_SUCCESS(ZydisEncoderEncodeInstruction(&req, encoded_instruction, &encoded_length)))
			{
				return FHEncodeFailed;
			}
			memcpy(changeHeader, encoded_instruction, encoded_length);
			changeHeader += encoded_length;
			if(farJump)
			{
				memcpy(changeHeader, changeHeader, 8);
				changeHeader += 8;
				instruction.length+=8;
			}
		} else {
			memcpy(changeHeader, readPointer, instruction.length);
			changeHeader += instruction.length;
		}
		readPointer += instruction.length;
		instructionPointer += instruction.length;
		length += instruction.length;
		if (length >= jmplen)
			break;
	}
	*poutold = (void*)(outfunc + 1);
	//now, we need to update the length of changed header
	*outfunc = changeHeader - (char*)*poutold;
	//generate a "jmp" back to oldfunc's body
	GenerateJmpLarge(outfunc + length + 1,(char*)oldfunc+length);
	changeHeader += GetJmpLenLarge();
	// backup old header for restoring old function in the future
	*changeHeader = length;
	memcpy(changeHeader + 1, oldfunc, length);

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
HookStatus UnHook(void* oldfunc, void* poutold)
{
	//see HookItSafe for jump func memory layout
	char* outfunc = (char*)poutold;
	int8_t length = *(outfunc - 1);
	outfunc += length + GetJmpLenLarge();
	length = *outfunc;
	if(RangeProtect(oldfunc,length,1)!=FHSuccess) return FHMprotectFail;
	memcpy(oldfunc,outfunc + 1,length);
	if(RangeProtect(oldfunc,length,0)!=FHSuccess) return FHMprotectFail;
	return FHSuccess;
}
