#!/usr/bin/env bash

for i in {1..100}; do echo $i; { time ./advanced_slubstick.elf ; } &>> output/advanced_slubstick; done
for i in {1..100}; do echo $i; { time ./dirty_page.elf ; } &>> output/dirty_page; done
for i in {1..100}; do echo $i; { time ./pipe_unlink.elf ; } &>> output/pipe_unlink; done
for i in {1..100}; do echo $i; { sleep 1; time timeout 3 ./stack_attack.elf -s9 ; } &>> output/stack_attack; done