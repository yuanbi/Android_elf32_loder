/* Copyright © 2014, Owen Shepherd
 *
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted without restriction.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES WITH
 * REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY
 * AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY SPECIAL, DIRECT,
 * INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM
 * LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE OR
 * OTHER TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR
 * PERFORMANCE OF THIS SOFTWARE.
 */
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/mman.h>
#include "elfload.h"

#define __ARM__

FILE *f;
void *buf;

typedef void (*entrypoint_t)(int (*putsp)(const char*));
typedef void ( *FnB2k_Access)(unsigned char* pAccessKey, unsigned char* pAccessSeed, unsigned short AccessLevel, unsigned char flagA0);
extern void el_free2();

static bool fpread(el_ctx *ctx, void *dest, size_t nb, size_t offset)
{
    (void) ctx;

    if (fseek(f, offset, SEEK_SET))
        return false;

    if (fread(dest, nb, 1, f) != 1)
        return false;

    return true;
}

static void *alloccb(
    el_ctx *ctx,
    Elf_Addr phys,
    Elf_Addr virt,
    Elf_Addr size)
{
    (void) ctx;
    (void) phys;
    (void) size;
    return (void*) virt;
}

static void check(el_status stat, const char* expln)
{
    if (stat) {
        fprintf(stderr, "%s: error %d\n", expln, stat);
        // exit(1);
    }
}

static void go(entrypoint_t ep)
{
    ep(puts);
}


//
// @brief 修复 got 表，内容来自 ida pro 的 dump
//
unsigned int repair_710dgot(unsigned char *path, unsigned char* base)
{
    FILE* fp = fopen(path, "rb");
    if(fp <= 0)
    {
        printf("!! Read file failed\n");
	return 1;
    }
    fseek(fp, 0, SEEK_END);
    unsigned int size = ftell(fp);
    rewind(fp);
    
    unsigned char* buf = malloc(size);
    if(buf == NULL)
    {

	printf("!! Malloc failed!\n");
	return 1;
    }

    memset(buf, 0, size);
    fread(buf, 1, size, fp);

    fclose(fp);

    // Work
    //


    // .got start = 0x006385C0 size = 0x2F30
    //
    unsigned char* got = base + 0x006385C0;
    for(unsigned int i = 0; i < size; i+=4)
    {
	unsigned int off = *(unsigned int*)(buf + i);
	*(unsigned int*)(got + i) = (unsigned int)off + (unsigned int)base;
	
	printf("Got repair mem off: %p old: %08x, new: %p\n", i, off, (off + base));
    }

    free(buf);

    return 0;
}

//
// @brief 修复外部导入函数，部分需要对 got 表修改
// 所以要先执行 repair_710dgot
//
unsigned int repair_710drel(unsigned char* base)
{
    unsigned char ins_ret[5] = {0x0E, 0xF0, 0xA0, 0xE1};

    // Repair File_Debug_CAPP
    //
    unsigned char* addr = base + 0x000795B8;
    memcpy(addr, ins_ret, 4);

    printf("Repaired File_Debug_CAPP!\n");

    // Repair printf
    //
    addr = base + 0x7930C;
    memcpy(addr, ins_ret, 4);

    printf("Repaired printf !\n");


    // Repair Print_Buffer
    //
    addr = base + 0x00080098;
    memcpy(addr, ins_ret, 4);

    printf("Repaired File_Debug_CAPP !\n");

    // Repair memcpy to memcpy2
    addr = base + 0x638F10; // = memcpy_ptr
    *(unsigned int*)addr = 0x293908 + (unsigned int)base;

    printf("Repaired memcpy !\n");

    // Repair strcpy to use_strcpy
    addr = base + 0x0638660; // strcpy_ptr
    *(unsigned int*)addr = 0x0049AB04 + (unsigned int)base;
    printf("Repaired strcpy !\n");

    return 0;
}

int main(int argc, char **argv)
{
    if (argc < 2) {
        fprintf(stderr, "usage: %s [elf-to-load]\n", argv[0]);
        return 1;
    }

    f = fopen(argv[1], "rb");
    if (!f) {
        perror("opening file");
        return 1;
    }

    el_ctx ctx;
    ctx.pread = fpread;
    ctx.elfpath = argv[1];

    printf("Loading %s start\n", ctx.elfpath);
    check(el_init(&ctx), "initialising");

    // Mem load
    //
    if (posix_memalign(&buf, ctx.align, ctx.memsz)) {
        perror("memalign");
        return 1;
    }

    if (mprotect(buf, ctx.memsz, PROT_READ | PROT_WRITE | PROT_EXEC)) {
        perror("mprotect");
        return 1;
    }

    ctx.base_load_vaddr = ctx.base_load_paddr = (uintptr_t) buf;

    check(el_load(&ctx, alloccb), "loading");
    check(el_relocate(&ctx), "relocating");

    uintptr_t epaddr = ctx.ehdr.e_entry + (uintptr_t) buf;

    entrypoint_t ep = (entrypoint_t) epaddr;
    FnB2k_Access B2k_Access = (FnB2k_Access)(buf + 0xC0B00);

    printf("Base addr %08x\n", ctx.base_load_paddr);

    // 修复 got 表
    //
    if(repair_710dgot("diag_got.bin", buf))
    {
	printf("Repair got failed!\n");
	exit(0);
    }

    // 导入函数修复
    //
    if(repair_710drel((unsigned char*)buf))
    {
	printf("Repair rel failed!\n");
	exit(0);
    }

    printf("Ready to run!\n");
    getchar();

    // 算法调用
    //
    unsigned char* seed = (unsigned char*)malloc(0x30);
    unsigned char* key = (unsigned char*)malloc(0x30);
    unsigned short AccessLevel = 0xC;
    unsigned char flagA0 = 1;

    memset(seed, 0, 0x30);
    memset(key, 0, 0x30);

    seed[0] = 0x03;
    seed[1] = 0x03;
    seed[2] = 0x03;
    seed[3] = 0x03;

    seed[4] = 0x03;
    seed[5] = 0x03;
    seed[6] = 0x03;
    seed[7] = 0x03;

#if 0
    // unsigned char* got = (unsigned char*)ctx.base_load_paddr + 0x6393C4;
    // *(unsigned int*)got = 0x0BD848 + (unsigned int)ctx.base_load_paddr;

    // get mem
    FILE* fp = fopen("mem.bin", "wb");
    fwrite((unsigned char*)(*(unsigned int*)got), 1, 0x100, fp);
    // fwrite((unsigned char*)ctx.base_load_paddr + 0x006385C0, 1, 0x2F30, fp);
    // fwrite((unsigned char*)ctx.base_load_paddr + 0x418ED4, 1, 0x100, fp);
    // fwrite((unsigned char*)ctx.base_load_paddr + 0x249BE8, 1, 0x100, fp);
    fclose(fp);
#endif

    B2k_Access(key, seed, AccessLevel, flagA0);
    for(int i = 0; i < 0x30; i++)
	printf("%02x,", key[i]);
    printf("\n");

    // go(ep);

    free(seed);
    free(key);

    fclose(f);
    el_free2();
    free(buf);

    return 0;
}
