/* Copyright © 2014, Owen Shepherd
 *
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES WITH
 * REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY
 * AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY SPECIAL, DIRECT,
 * INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM
 * LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE OR
 * OTHER TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR
 * PERFORMANCE OF THIS SOFTWARE.
 */

#include "elfload.h"
#include <stdlib.h>

#define __ARM__
#if defined(__ARM__)

#define R_ARM_NONE     0
#define R_ARM_ABS32    0x02
#define R_ARM_RELATIVE 0x17
#define R_ARM_GLOB_DAT 0x15
#define R_ARM_JUMP_SLOT  0x16


unsigned char* g_buf = NULL;



unsigned int el_init2(char* path)
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
    
    g_buf = malloc(size);
    if(g_buf == NULL)
    {

	printf("!! Malloc failed!\n");
	return 1;
    }

    memset(g_buf, 0, size);
    fread(g_buf, 1, size, fp);

    fclose(fp);

    return 0;
}

void el_free2()
{
    if(g_buf)
    {
	free(g_buf);
    }
}


el_status el_getsymbyid(el_ctx *ctx, unsigned int id, Elf_Sym** sym)
{
    if(g_buf == NULL)
    {
        if(el_init2(ctx->elfpath))
	{
	    printf("!! Init2 falied!\n");
	    exit(0);
	    return 1;
	}
    }

    Elf32_Ehdr* ehdr = (Elf32_Ehdr*)g_buf;
    Elf32_Shdr* shdr = (Elf32_Shdr*)(g_buf + ehdr->e_shoff);
    unsigned int shnum = ehdr->e_shnum;
    shnum = ehdr->e_shnum == 0 ? shdr[0].sh_size : ehdr->e_shnum;

    int i = 0;
    for(i = 0; i < shnum; i++)
    {
	if(shdr[i].sh_type != SHT_DYNSYM)
	    continue;

	shdr = &shdr[i];
	break;
    }

    if(i == shnum)
    {
        printf("!! Not finded .dynsym\n");
	exit(0);
    }

    unsigned int entry_num = shdr->sh_size / shdr->sh_entsize;

     if(id > entry_num)
     {
 	printf("!! Invalid sym id, max_sym=%08x req_sym=%08x\n", entry_num, id);
 	exit(0);
     }

     Elf32_Sym* syms = (Elf32_Sym*)(g_buf + shdr->sh_offset);

    *sym = &syms[id];

    return 0;
}

el_status el_applyrela(el_ctx *ctx, Elf_RelA *rel)
{
    uintptr_t *p = (uintptr_t*) (rel->r_offset + ctx->base_load_paddr);
    uint32_t type = ELF_R_TYPE(rel->r_info);
    uint32_t sym  = ELF_R_SYM(rel->r_info);

    switch (type) {
        case R_ARM_NONE:
            EL_DEBUG("R_AARCH64_NONE\n");
            break;

        case R_ARM_ABS32:
            if (sym) {
                EL_DEBUG("R_ARM_ABS32 with symbol ref!A\n");
                return 0;
                return EL_BADREL;
            }

            EL_DEBUG("Applying R_ARM_ABS32 reloc @%p !A\n", p);
            *p = rel->r_addend + ctx->base_load_vaddr;
            break;

	case R_ARM_RELATIVE:
            if (sym) {
                EL_DEBUG("R_ARM_RELATIVE with symbol ref!A\n");
                return EL_BADREL;
            }

            EL_DEBUG("Applying R_ARM_RELATIVE reloc @%p!A\n", p);
            *p = rel->r_addend + ctx->base_load_vaddr;
            break;

	case R_ARM_JUMP_SLOT:
            if (sym) {
                EL_DEBUG("R_ARM_JUMP_SLOT with symbol ref!A\n");
                return EL_BADREL;
            }

            EL_DEBUG("Applying R_ARM_JUMP_SLOT reloc @%p!A\n", p);
            *p = rel->r_addend + ctx->base_load_vaddr;
            break;

        default:
            EL_DEBUG("Bad relocation A %u\n", type);
            return 0;
            return EL_BADREL;

    }

    return EL_OK;
}

el_status el_applyrel(el_ctx *ctx, Elf_Rel *rel)
{
    uintptr_t *p = (uintptr_t*) (rel->r_offset + ctx->base_load_paddr);
    uint32_t type = ELF_R_TYPE(rel->r_info);
    uint32_t sym  = ELF_R_SYM(rel->r_info);
    uint32_t info = ELF32_R_INFO(sym, type);
    uint32_t bind = ELF32_ST_BIND(rel->r_info);

    switch (type) {
        case R_ARM_NONE:
            EL_DEBUG("R_AARCH64_NONE\n");
            break;

        case R_ARM_ABS32:
	    if(!sym)
	    {
                EL_DEBUG("R_ARM_JUMP_SLOT with no symbol ref!\n");
                return EL_BADREL;
            }

            EL_DEBUG("Applying R_ARM_ABS32 reloc @%p\n", p);

	    Elf_Sym* _sym = NULL;
	    if(el_getsymbyid(ctx, rel->r_info >> 8, &_sym))
	    {
		printf("!! Reloc get sym failed!\n");
		exit(0);
	    }
            *p += (unsigned char*)ctx->base_load_vaddr + _sym->st_value;
            break;

	case R_ARM_RELATIVE:

            EL_DEBUG("Applying R_ARM_RELATIVE reloc @%p\n", p);
            *p += ctx->base_load_vaddr;
            break;

	case R_ARM_JUMP_SLOT:
            if (sym) {
                EL_DEBUG("R_ARM_JUMP_SLOT with symbol ref!\n");
                return EL_BADREL;
            }

            EL_DEBUG("Applying R_ARM_JUMP_SLOT reloc @%p\n", p);
            *p += ctx->base_load_vaddr;
            break;

        default:
            EL_DEBUG("Bad relocation %u\n", type);
            return 0;
            return EL_BADREL;

    }

    return EL_OK;
}


#endif
