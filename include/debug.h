#pragma once
#include <stdio.h>
#include <string.h>
#include <errno.h>

enum AnsiColor
{
  Ansi_Red = 31,
  Ansi_Green = 32,
  Ansi_Yellow = 33,
  Ansi_Blue = 34,
  Ansi_Magenta = 35,
  Ansi_Cyan = 36,
  Ansi_White = 37,
};

size_t DEBUG = 0;
size_t INFO = 1;
size_t SUCCESS = 1;
size_t ERROR = 1;

#define DEBUG_NO_COLOR

#ifndef DEBUG_NO_COLOR
#define DEBUG_FORMAT_STRING "\033[1;%zum[%-1s]\033[0;39m "
#define PRINTF_INFO(x) DEBUG_FORMAT_STRING, debug_colors[x], debug_labels[x]
#define PRINTF_DEBUG(x) DEBUG_FORMAT_STRING "[%6d] ", debug_colors[x], debug_labels[x], gettid()
#else
#define DEBUG_FORMAT_STRING "[%-1s] "
#define PRINTF_INFO(x) DEBUG_FORMAT_STRING, debug_labels[x]
#define PRINTF_DEBUG(x) DEBUG_FORMAT_STRING "[%6d] ", debug_labels[x], gettid()
#endif

#define debug_debug(...) do { if (DEBUG) { printf(PRINTF_DEBUG(0)); printf(__VA_ARGS__); } } while (0)
#define debug_info(...) do { if (INFO) { printf(PRINTF_INFO(0)); printf(__VA_ARGS__); } } while (0)
#define debug_success(...) do { if (SUCCESS) { printf(PRINTF_INFO(1)); printf(__VA_ARGS__); } } while (0)
#define debug_error(...) do { if (ERROR) { printf(PRINTF_INFO(2)); printf(__VA_ARGS__); exit(-1); } } while (0)
#define debug_print(...) do { printf(PRINTF_INFO(0)); printf(__VA_ARGS__); } while (0)

// static int current_stage = 0;
// __attribute__((unused))static void next_stage(void)
// {
//   current_stage++;
// }
static const char* debug_labels[] =
{
  "*", "+", "!"
};
static const size_t debug_colors[] =
{
  Ansi_Cyan, Ansi_Green, Ansi_Red
};
__attribute__((unused))static void hex_dump(size_t* addresses, size_t length)
{
  for (size_t i = 0; i < length; ++i)
  {
    debug_info("0x%016lx\n", addresses[i]);
  }
}

void wait_input(void)
{
	debug_print("> ");
	getchar();
}

#define MAX_TIME 4096
#define RATIO 2
#define MAX_TIME_VAL 128
void print_ptrs_times(size_t *ptrs, size_t *times, size_t size)
{
    size_t max = 0;
    size_t min = -1;
    size_t adjusted_time;

    for (size_t i = 0; i < size; ++i) {
        if (times[i] > max && times[i] < 4000 + max)
            max = times[i];
        if (times[i] < min)
            min = times[i];
    }

    for (size_t i = 0; i < size; ++i) {
        adjusted_time = (times[i] - min) * MAX_TIME_VAL / max;
        printf("% 5ld:% 7ld:%016zx:", i, times[i], ptrs[i]);
        for (size_t j = 0; j < adjusted_time; ++j)
            printf("#");
        printf("\n");
    }
}
void print_times(size_t *times, size_t size)
{
    size_t max = 0;
    size_t min = -1;
    size_t adjusted_time;

    for (size_t i = 0; i < size; ++i) {
        if (times[i] > max && times[i] < 4000 + max)
            max = times[i];
        if (times[i] < min)
            min = times[i];
    }

    for (size_t i = 0; i < size; ++i) {
        adjusted_time = (times[i] - min) * MAX_TIME_VAL / max;
        printf("% 5ld:% 7ld:", i, times[i]);
        for (size_t j = 0; j < adjusted_time; ++j)
            printf("#");
        printf("\n");
    }
}
void print_hist(size_t *times, size_t size)
{
    size_t start_time = 0;
    size_t end_time = MAX_TIME;
    size_t hist[MAX_TIME];
    memset(hist, 0, sizeof(hist));

    for (size_t i = 0; i < size; ++i)
        if (times[i]/RATIO < MAX_TIME)
            ++hist[times[i]/RATIO];

    for (size_t i = 0; i < MAX_TIME; ++i) {
        if (hist[i] > 3) {
            start_time = i;
            break;
        }
    }

    for (ssize_t i = MAX_TIME; i >= 0; --i) {
        if (hist[i] > 3) {
            end_time = i;
            break;
        }
    }

    for (size_t i = start_time; i < end_time; ++i) {
        printf("% 5ld:", i*RATIO);
        for (size_t j = 0; j < hist[i]; ++j)
            printf("#");
        printf("\n");
    }
}