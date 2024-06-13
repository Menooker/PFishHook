#include "PFishHook.h"
#include <Zydis/Zydis.h>
#include <inttypes.h>
#include <iostream>
#include <sstream>
#include <stdint.h>
#include <stdio.h>
#include <string>
#include <vector>

int main();

asm("testfunc:\n\
ja gofurther2\n\
gofurther:\n\
	call  main\n\
gofurther2:\n\
	call  main\n\
");
extern "C" void testfunc();
extern "C" int gofurther2;

void (*poldfunc)();
void test_replace() { return poldfunc(); }

asm(R"(testfunc2:
jne gofurther3
cmpl   $0x0,0x10(%rip)
testfunc2_jmp_back:
ja gofurther4
ja gofurther5
gofurther3:
	call  main
gofurther4:
	call  main
gofurther5:
	call  main
)");
extern "C" void testfunc2();
extern "C" int testfunc2_jmp_back;
extern "C" int gofurther3;
extern "C" int gofurther4;
extern "C" int gofurther5;

extern "C" void testfunc_lea();
asm(R"(testfunc_lea:
lea 0x123450(%rip),%ecx
testfunc_lea_jmp_back:
lea 0x123450(%rip),%rcx
ret
)");
extern "C" int testfunc_lea_jmp_back;

volatile int check_mask = 0;

void (*poldfunc5)();
void (*poldfunc6)();
void (*poldfunc7)();
void test_dummy() {
    printf("DUMMY: orig func\n");
    check_mask |= 1;
}
void test_replace_d() {
    printf("shadow 1\n");
    check_mask |= (1 << 1);
    return poldfunc5();
}
void test_replace_d2() {
    printf("shadow 2\n");
    check_mask |= (1 << 2);
    return poldfunc6();
}
void test_replace_d3() {
    printf("shadow 3\n");
    check_mask |= (1 << 3);
    return poldfunc7();
}
void test_replace2() { return; }

struct ExpectedCode {
    enum Kind { CODE, DATA32, DATA64 } kind;
    union {
        const char *code;
        int32_t data32;
        int64_t data64;
    };
    size_t numInstructions;
    ExpectedCode(const char *code, size_t numInstructions)
        : kind{CODE}, code{code}, numInstructions{numInstructions} {}
    ExpectedCode(int32_t data) : kind{DATA32}, data32{data} {}
    ExpectedCode(int64_t data) : kind{DATA64}, data64{data} {}
};

static std::string disas(ZydisFormatter &formatter, ZydisDecoder &decoder,
                         uint8_t *f, int sz, bool print,
                         uint8_t **out = nullptr) {
    std::stringstream ss;
    uint8_t *readPointer = (uint8_t *)f;
    ZydisDecodedInstruction instruction;
    while (ZYDIS_SUCCESS(ZydisDecoderDecodeBuffer(
        &decoder, readPointer, 128, (uint64_t)readPointer, &instruction))) {
        char buffer[256];
        ZydisFormatterFormatInstruction(&formatter, &instruction, buffer,
                                        sizeof(buffer));
        if (print) {
            printf("%p: %s\n", readPointer, buffer);
        }
        ss << buffer << '\n';
        readPointer += instruction.length;
        sz--;
        if (sz <= 0)
            break;
    }
    if (out)
        *out = readPointer;
    return ss.str();
}

static void checkASM(ZydisFormatter &formatter, ZydisDecoder &decoder,
                     void *target,
                     const std::vector<ExpectedCode> &expectedAfterHook) {
    uint8_t *resolvePosition = (uint8_t *)target;
    for (auto &expected : expectedAfterHook) {
        if (expected.kind == ExpectedCode::CODE) {
            auto hooked =
                disas(formatter, decoder, resolvePosition,
                      expected.numInstructions, true, &resolvePosition);
            if (hooked != expected.code) {
                printf("\nUnexpected ASM result. Expecting\n%s\n",
                       expected.code);
                exit(2);
            }
        } else if (expected.kind == ExpectedCode::DATA64) {
            printf("%p: [data64]\n", resolvePosition);
            int64_t val = *(int64_t *)resolvePosition;
            if (expected.data64 != val) {
                printf("\nUnexpected data64 result. Expecting %ld, met %ld\n",
                       expected.data64, val);
                exit(2);
            }
            resolvePosition += 8;
        } else {
            printf("%p: [data32]\n", resolvePosition);
            int32_t val = *(int32_t *)resolvePosition;
            if (expected.data32 != val) {
                printf("\nUnexpected data32 result. Expecting %d, met %d\n",
                       expected.data32, val);
                exit(2);
            }
            resolvePosition += 4;
        }
    }
}

typedef void (*functype)();
static void runhook(ZydisFormatter &formatter, ZydisDecoder &decoder,
                    const char *name, functype target, functype *old,
                    functype newfunc, size_t origsize) {
    printf("==============================\n%s\n==========================="
           "===\nBefore Hook:\n",
           name);
    disas(formatter, decoder, (uint8_t *)target, origsize, true);
    fputs("\n================\n", stdout);
    auto ret = HookIt((void *)target, (void **)old, (void *)newfunc);
    printf("Hook status=%d\n", ret);
    if (ret != FHSuccess) {
        printf("Failed to hook\n");
        exit(2);
    }
}

static void test_ja_call(ZydisFormatter &formatter, ZydisDecoder &decoder) {
    runhook(formatter, decoder, "testfunc", testfunc, &poldfunc, test_replace,
            3);
    char code[256];
    snprintf(code, 255,
             R"(jmp 0x%016lX
int3
int3
call 0x%016lX
)",
             (uintptr_t)&test_replace, (uintptr_t)&main);
    printf("After Hook:\n");
    checkASM(formatter, decoder, (void *)testfunc, {{code, 4}});

    printf("\nShadow Func:\n");
    snprintf(code, 255,
             R"(jnbe 0x%016lX
call 0x%016lX
jmp [0x%016lX]
)",
             0x15 + (uintptr_t)poldfunc, (uintptr_t)&main,
             0xd + (uintptr_t)poldfunc);
    char code2[256];
    snprintf(code2, 255,
             R"(jmp [0x%016lX]
)",
             0x1B + (uintptr_t)poldfunc);
    checkASM(formatter, decoder, (void *)poldfunc,
             {{code, 3},
              {int64_t((intptr_t)&gofurther2)},
              {code2, 1},
              {int64_t((intptr_t)&gofurther2)}});
}

static void test_jne_cmp(ZydisFormatter &formatter, ZydisDecoder &decoder) {
    void (*poldfunc2)();
    runhook(formatter, decoder, "testfunc2", testfunc2, &poldfunc2,
            test_replace2, 4);
    char code[256];
    snprintf(code, 255,
             R"(jmp 0x%016lX
int3
int3
int3
int3
jnbe 0x%016lX
jnbe 0x%016lX
)",
             (uintptr_t)&test_replace2, (uintptr_t)&gofurther4,
             (uintptr_t)&gofurther5);
    printf("After Hook:\n");
    checkASM(formatter, decoder, (void *)testfunc2, {{code, 7}});

    printf("\nShadow Func:\n");
    snprintf(code, 255,
             R"(jnz 0x%016lX
cmp dword ptr [0x%016lX], 0x00
jmp [0x%016lX]
)",
             0x17 + (uintptr_t)poldfunc2, (uintptr_t)&testfunc2 + 0x19,
             0xf + (uintptr_t)poldfunc2);
    char code2[256];
    snprintf(code2, 255,
             R"(jmp [0x%016lX]
)",
             0x1D + (uintptr_t)poldfunc2);
    checkASM(formatter, decoder, (void *)poldfunc2,
             {{code, 3},
              {int64_t((intptr_t)&testfunc2_jmp_back)},
              {code2, 1},
              {int64_t((intptr_t)&gofurther3)}});
}

static void test_lea(ZydisFormatter &formatter, ZydisDecoder &decoder) {
    void (*poldfunc2)();
    runhook(formatter, decoder, "testfunc_lea", testfunc_lea, &poldfunc2,
            test_replace2, 3);
    char code[256];
    snprintf(code, 255,
             R"(jmp 0x%016lX
int3
lea rcx, [0x%016lX]
ret
)",
             (uintptr_t)&test_replace2, (uintptr_t)&testfunc_lea + 0x12345d);
    printf("After Hook:\n");
    checkASM(formatter, decoder, (void *)testfunc_lea, {{code, 4}});

    printf("\nShadow Func:\n");
    snprintf(code, 255,
             R"(lea ecx, [0x%016lX]
jmp [0x%016lX]
)",
             (uintptr_t)&testfunc_lea + 0x123456, (uintptr_t)poldfunc2 + 0xc);
    checkASM(formatter, decoder, (void *)poldfunc2,
             {{code, 2}, {int64_t((intptr_t)&testfunc_lea_jmp_back)}});
}


void test_multi_hook(ZydisFormatter &formatter, ZydisDecoder &decoder) {
    // test for dup hooks
    printf("running multi-hook checks\n");
    runhook(formatter, decoder, "testfunc_dup", test_dummy, &poldfunc5,
            test_replace_d, 5);
    runhook(formatter, decoder, "testfunc_dup2", test_dummy, &poldfunc6,
            test_replace_d2, 5);
    runhook(formatter, decoder, "testfunc_dup3", test_dummy, &poldfunc7,
            test_replace_d3, 5);
    test_dummy();
    if (check_mask != (1 << 4) - 1) {
        printf("\nUnexpected checkmask. Expecting %d, got %d\n", (1 << 5) - 1,
               check_mask);
        exit(2);
    }
}

int main() {
    ZydisFormatter formatter;
    ZydisFormatterInit(&formatter, ZYDIS_FORMATTER_STYLE_INTEL);
    // ZydisFormatterSetProperty(&formatter, ZYDIS_FORMATTER_PROP_ADDR_FORMAT,
    // ZYDIS_ADDR_FORMAT_RELATIVE_UNSIGNED);
    ZydisDecoder decoder;
    ZydisDecoderInit(&decoder, ZYDIS_MACHINE_MODE_LONG_64,
                     ZYDIS_ADDRESS_WIDTH_64);

    printf("main=%p\ntest_replace=%p\ntest_replace2=%p\n", main, test_replace,
           test_replace2);
    test_ja_call(formatter, decoder);
    test_jne_cmp(formatter, decoder);
    test_lea(formatter, decoder);
	test_multi_hook(formatter, decoder);
    printf("All tests are done\n");
    return 0;
}
