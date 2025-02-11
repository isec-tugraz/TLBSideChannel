#pragma once

#define _GNU_SOURCE
#include <time.h>
#include <sched.h>
#include <time.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <sys/resource.h>

void set_limit(void)
{
    int ret;
    struct rlimit l = {
        .rlim_cur = 100000,
        .rlim_max = 100000,
    };
    ret = setrlimit(RLIMIT_NOFILE, &l);
    if (ret < 0) {
        perror("setrlimit");
        exit(-1);
    }
}

void pin_to_core(size_t core)
{
    int ret;
    cpu_set_t cpuset;

    CPU_ZERO(&cpuset);
    CPU_SET(core, &cpuset);

    ret = sched_setaffinity(0, sizeof(cpu_set_t), &cpuset);
    if (ret) {
        perror("sched_setaffinity: ");
        exit(-1);
    }
}

size_t mem_total_rounded;
void get_total_memory(void)
{
    FILE *fp;
    char input[100];

    size_t mem_total_kb;

    /* Open the command for reading. */
    fp = popen("awk '/MemTotal/ { print $2 }' /proc/meminfo", "r");
    if (fp == NULL) {
        printf("[!] Failed to get MemTotal\n" );
        exit(1);
    }

    /* Read the output a line at a time - output it. */
    if (fgets(input, sizeof(input), fp) != NULL) {
        mem_total_kb = atoi(input);
        if (mem_total_kb == 0) {
            printf("[!] Failed to convert MemTotal\n" );
            exit(1);
        }
        mem_total_rounded = (mem_total_kb+(1<<20)-1)/(1<<20) << 30; 
        printf("[*] MemTotal: %luB\n", mem_total_rounded);
    }
    else {
        printf("[!] Failed to get MemTotal\n" );
        exit(1);
    }

    /* close */
    pclose(fp);
}