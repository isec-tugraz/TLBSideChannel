#!/usr/bin/env bash

for i in {1..100}; do echo $i; { sleep 1; time ./stack_leak.elf ; } &>> output/stack_leak; done