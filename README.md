# Artifacts of an Advanced TLB Side-Channel Attack

This repository contains artifacts developed during a research project, as well as the code to perform the advanced TLB side channel of the paper "When Good Kernel Defenses Go Bad: Reliable and Stable Kernel Exploits via Defense-Amplified TLB Side-Channel Leaks", which got accepted at USENIX Security '25.

## Abstract

The paper shows how side-channel leakage in kernel defenses can be exploited to leak the locations of security-critical kernel objects, enabling reliable and stable attacks on the Linux kernel. By systematically analyzing 127 defenses, we show that enabling any of three specific defenses - strict memory permissions, kernel heap virtualization, or stack virtualization - exposes fine-grained TLB contention patterns. These patterns are then combined with kernel allocator massaging to perform location disclosure attacks, revealing the locations of kernel heap objects, page tables, and stacks.

The artifacts demonstrate the timing side-channel attack and the exploit techniques. For both, we provide a kernel module and programs to perform the experiments.

 1. For the timing side channel, we leak the location of kernel heap objects (i.e., `pipe_buffer`, `msg_msg`, `cred`, `file`, and `seq_file`), page tables (all levels), and the kernel stack. While our side channel works on all Intel generations between the 8th and 14th, we recommend evaluating on Intel 13th generation, as we have mainly evaluated on this one. While our side channel works on Linux kernels between v5.15 and v6.8, we recommend evaluating on the Ubuntu generic kernel v6.8.
 2. For the exploit techniques, we perform privilege escalation using the 3 techniques. Inherent to kernel exploitation, we tailor these techniques to the specific Ubuntu generic kernel v6.8.0-38, the required version to evaluate these techniques.

## Description & Requirements

### Security, Privacy, and Ethical Concerns

For evaluating the timing side channel, the experiments can be used in kernel exploitation of memory-corruption attacks, as they allow the location of kernel objects be leaked on Intel CPUs. This raises potential ethical concerns.

For evaluating the exploit techniques, the artifacts might result in destructive steps. While we introduce an exploit primitive via a kernel module and do not provide methods to compromise systems in the wild, the experiment using this primitive may cause system crashes. However, during our evaluation, we have not encountered a single system crash.

### How to Access

We provide the source code ([github](https://github.com/isec-tugraz/TLBSideChannel/tree/artifact-evaluation)) for performing the timing side channel.

### Hardware Dependencies

A Linux system running on an Intel CPU between 8th and 14th generation. However, we recommend running the evaluation on a 13th generation Intel, as this is what we have mainly evaluated on. We have observed a trend that newer Intel CPUs and better cooling tend to give more stable results.

### Software Dependencies

While our disclosure attacks should generically work on Linux kernels, our experiments are tailored to Ubuntu Linux kernels between v5.15 to v6.8. As reference, we have mainly evaluated on the generic Ubuntu kernel v6.8.0-38 (and the kernel with `CONFIG_SLAB_VIRTUAL` of v6.6 ([patch](https://lore.kernel.org/all/CAHKB1wLetbLZjhg1UVhA1QwZHo226BRL=Khm962JEfh0F+CVbQ@mail.gmail.com/T/))).

One part of the artifact evaluation is to insert a kernel module that requires *root privileges*. This module is required to obtain the ground truth of the kernel object's location as well as for providing the exploit primitive for the exploit techniques. We tested our kernel module on Ubuntu Linux downstream kernels v5.15, v6.5, and v6.8 and kernel v6.6. For other kernels that have different config files (or other downstream changes) our implemented module may not do what we intended. Specifically, in order to obtain the location of kernel objects, we redefined and reimplemented structures and functions. We did this because some functions used to access kernel data structures are implemented as inline functions, e.g., `ipc_obtain_object_check`, which prevented us from calling these functions directly. Another reason is that some structs, e.g., `msg_queue`, are defined in c files, which also prevents us from using these struct definitions.

While this artifact evaluation include experiments exploiting leakage for all defenses, we only recommend to reproduce experiments exploiting leakage from **D1** and **D3**. This is because reproducing leakage from **D2** requires a Linux kernel compiled with **CONFIG_SLAB_VIRTUAL**, i.e., the intended v6.6 used by Google's KernelCTF. We encountered driver crashes during boot due to incompatibilities, requiring additional engineering effort. However, all of our heap location leakage attacks should work directly by exploiting **D2** when swapping the base address from the DPM to the virtual heap.

Due to the nature of kernel exploitation in general, our exploit techniques depend on the kernel version. Therefore, we only provide the end-to-end attack for the exact Ubuntu Linux kernel v6.8.0-38 (and the kernel with **CONFIG_SLAB_VIRTUAL** of v6.6). The exact version is needed, e.g., for the control-flow hijacking attack, as the ROP chain varies between versions. Similarly, the other two exploit techniques require internal version-dependent kernel information. Curically, all information can be obtained as an unprivileged user but requires engineering effort.

## Set-Up

### Installation

The installation required to perform artifact evaluation works as following:

 1. Clone our github repository ([github](https://github.com/isec-tugraz/TLBSideChannel/tree/artifact-evaluation)) to `/repo/path` directory.
 2. Change directory to `/repo/path`.
 3. Select in `./lkm.c` either `V5_15`, `V6_5`, `V6_6`, or `V6_8`, depending on your running Ubuntu Linux kernel version.
 4. Execute `make init` to build the kernel module and all experiments and insert the kernel module.

### Basic Test

Before starting the experiments, determine the TLB hit thresholds on your CPU as follows. It is important to ensure that the background noise is as low as possible before starting this basic experiment, as described in **Notes on Reusability**.

 1. Change directory to `/repo/path/generic`.
 2. Execute `./threshold_detection.elf` prints `[+] detected thresholds: <THRESHOLD> <THRESHOLD2>`, where `THRESHOLD` is the threshold for capturing 97 % of all hit timings of mapped addresses and `THRESHOLD2` is the threshold for the minimum timing of unmapped addresses.
 3. Repeat this a few times and write the most consistent result to `THRESHOLD` and `THRESHOLD2` in `./include/tlb_flush.h` and recompile with `make build` in `/repo/path`.

## Experiments

Before running the experiments, please perform **Set-Up** and read **Notes on Reusability**.

#### Basic DPM location leakage [10 human-seconds + 1 computer-second] (E1)

_How to:_
Execute `./generic/dpm_leak.elf`.

_Results:_
This experiment outputs the base address of the DPM.

#### Basic `vmalloc` memory location leakage [10 human-seconds + 1 computer-second] (E2)

_How to:_
Execute `./generic/vmalloc_leak.elf`.

_Results:_
This experiment outputs the base address of the virtual memory section used for `vmalloc`.

#### Basic `vmemmap` memory location leakage [10 human-seconds + 1 computer-second] (E3)

_How to:_
Execute `./generic/vmemmap_leak.elf`.

_Results:_
This experiment outputs the base address of the virtual memory mapping `vmemmap`.

#### `msg_msg` location leakage [10 human-seconds + 10 computer-seconds] (E4)

_How to:_
Execute `./heap/msg_msg_leak.elf`.

_Results:_
This experiment outputs the page-aligned `msg_msg` object location.

#### `file` location leakage [10 human-seconds + 10 computer-seconds] (E5)

_How to:_
Execute `./heap/file_leak.elf`.

_Results:_
This experiment outputs the page-aligned `file` object location.

#### `seq_file` location leakage [10 human-seconds + 10 computer-seconds] (E6)

_How to:_
Execute `./heap/seq_file_leak.elf`.

_Results:_
This experiment outputs the page-aligned `seq_file` object location.

#### `pipe_buffer` location leakage [10 human-seconds + 10 computer-seconds] (E7)

_How to:_
Execute `./heap/pipe_buffer_leak.elf`.

_Results:_
This experiment outputs the page-aligned `pipe_buffer` object location.

#### Page-table location leakage [10 human-seconds + 20 computer-seconds] (E8)

_How to:_
Execute `./page-table/pt_leak.elf`, `./page-table/pmd_leak.elf`, or `./page-table/pud_leak.elf`.

_Results:_
This experiment outputs the respective location of PT, PMD, and PUD.

#### Reliable location disclosure attacks [5 human-minute + 2 computer-hours] (E10)

_How to:_
Execute `./eval.sh` (in `heap`, `page-table` and `stack`) and then `./print.py`.
        
_Description:_
The `./eval.sh` scripts performs between 20 to 100 execution of (E4-9) depending on the experiment, while `./print.py` prints a table which should closely resemble Table 1. As described in A.5, background activity should be minimized in this evaluation.

_Results:_
This experiment outputs the content of Table 1 for **D1** and **D3**.

#### Unlink primitive [10 human-seconds + 1 computer-seconds] (E11)

_How to:_
Execute `./attacks/pipe_unlink.elf`.
        
_Limitation:_
Works with Ubuntu kernel v6.8.0-38. Other versions will most likely lead to a program crash.

_Results:_
Privilege escalation.

#### Use-After-Free & Out-Of-Bounds write [10 human-seconds + 1 computer-seconds] (E12)

_How to:_
Execute `./attacks/dirty_page.elf` or `./attacks/advanced_slubstick.elf`.
        
_Limitation:_
Works with Ubuntu kernel v6.8.0-38 or the v6.6 intended to be used with `CONFIG_SLAB_VIRTUAL`. Other versions will most likely lead to a program crash.

_Results:_
Privilege escalation.

#### Constrained write [10 human-seconds + 3 computer-seconds] (E13)

_How to:_
Execute `./attacks/stack_attack.elf`.
        
_Limitation:_
Works with Ubuntu kernel v6.8.0-38. Other versions will most likely lead to a program crash.

_Results:_
Privilege escalation.

#### Reliable exploit techniques [5 human-minutes + 10 computer-minutes] (E14)

_How to:_
Execute `./attacks/eval.sh` and then `./attacks/print.py`, both in `attacks`.
        
_Results:_
This experiment shows the success rate of the 3 exploit techniques.

## Notes on Reusability

As described in Section 6.2 **Stress**, the most dominant noise source is CPU frequency fluctuation. Hence, perform all experiments with as little background activity as possible to reproduce the paper's results. We even suggest to perform the experiments on an idle system with no other activity.
