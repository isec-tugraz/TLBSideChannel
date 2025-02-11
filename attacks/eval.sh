#!/usr/bin/env bash

for i in {1..100}; do echo $i; { time ./advanced_slubstick.elf ; } &>> output/advanced_slubstick; done
for i in {1..100}; do echo $i; { time ./dirty_page.elf ; } &>> output/dirty_page; done
for i in {1..100}; do echo $i; { time ./pipe_unlink.elf ; } &>> output/pipe_unlink; done
for i in {1..100}; do echo $i; { sleep 0.5; time ./stack_attack.elf ; } &>> output/stack_attack; done