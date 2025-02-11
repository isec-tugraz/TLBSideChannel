#ifndef CACHEUTILS_H
#define CACHEUTILS_H

#ifndef HIDEMINMAX
#define MAX(X,Y) (((X) > (Y)) ? (X) : (Y))
#define MIN(X,Y) (((X) < (Y)) ? (X) : (Y))
#endif

void maccess(void *p) { asm volatile("movq (%0), %%rax\n" : : "c"(p) : "rax"); }

inline size_t rdtsc_nofence(void)
{
  size_t a, d;
  asm volatile ("rdtsc" : "=a" (a), "=d" (d));
  a = (d<<32) | a;
  return a;
}

inline size_t rdtsc(void)
{
  size_t a, d;
  asm volatile ("mfence");
  asm volatile ("rdtsc" : "=a" (a), "=d" (d));
  a = (d<<32) | a;
  asm volatile ("mfence");
  return a;
}

inline size_t rdtsc_cpuid_begin() {
  size_t a, d;
  asm volatile ("mfence\n\t"
    "RDTSCP\n\t"
    "mov %%rdx, %0\n\t"
    "mov %%rax, %1\n\t"
    "xor %%rax, %%rax\n\t"
    "CPUID\n\t"
    : "=r" (d), "=r" (a)
    :
    : "%rax", "%rbx", "%rcx", "%rdx");
  a = (d<<32) | a;
  return a;
}

inline size_t rdtsc_cpuid_end() {
  size_t a, d;
  asm volatile(
    "xor %%rax, %%rax\n\t"
    "CPUID\n\t"
    "RDTSCP\n\t"
    "mov %%rdx, %0\n\t"
    "mov %%rax, %1\n\t"
    "mfence\n\t"
    : "=r" (d), "=r" (a)
    :
    : "%rax", "%rbx", "%rcx", "%rdx");
  a = (d<<32) | a;
  return a;
}


inline size_t rdtsc_begin(void)
{
  size_t a, d;
  asm volatile ("mfence");
  asm volatile ("rdtsc" : "=a" (a), "=d" (d));
  a = (d<<32) | a;
  asm volatile ("lfence");
  return a;
}

inline size_t rdtsc_end(void)
{
  size_t a, d;
  asm volatile ("lfence");
  asm volatile ("rdtsc" : "=a" (a), "=d" (d));
  a = (d<<32) | a;
  asm volatile ("mfence");
  return a;
}

inline void flush(__attribute__((unused))size_t p)
{
  asm volatile (".intel_syntax noprefix");
  asm volatile ("clflush qword ptr [%0]\n" : : "r" (p));
  asm volatile (".att_syntax");
}

inline void prefetcht0(void* p)
{
  asm volatile ("prefetcht0 (%0)" : : "r" (p));
}

inline void prefetcht1(void* p)
{
  asm volatile ("prefetcht1 (%0)" : : "r" (p));
}

inline void prefetcht2(void* p)
{
  asm volatile ("prefetcht2 (%0)" : : "r" (p));
}

inline void prefetchnta(void* p)
{
  asm volatile ("prefetchnta (%0)" : : "r" (p));
}

// ---------------------------------------------------------------------------
inline void prefetch2(void* p)
{
  asm volatile ("prefetchnta (%0)" : : "a" (p));
  asm volatile ("prefetcht2 (%0)" : : "a" (p));
}


inline void prefetch(__attribute__((unused))size_t p)
{
  asm volatile (".intel_syntax noprefix");
  asm volatile ("prefetchnta qword ptr [%0]" : : "r" (p));
  asm volatile ("prefetcht2 qword ptr [%0]" : : "r" (p));
  asm volatile (".att_syntax");
}

inline void longnop(void)
{
  asm volatile ("nop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\n"
                "nop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\n"
                "nop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\n"
                "nop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\n"
                "nop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\n"
                "nop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\n"
                "nop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\n"
                "nop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\n");
}

#endif
