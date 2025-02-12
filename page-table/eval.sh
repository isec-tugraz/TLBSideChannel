#!/usr/bin/env bash

for i in {1..20}; do echo $i; { sleep 2; time ./pt_leak.elf ; } &>> output/pt_leak; done
for i in {1..20}; do echo $i; { sleep 2; time ./pmd_leak.elf ; } &>> output/pmd_leak; done
for i in {1..20}; do echo $i; { sleep 2; time ./pud_leak.elf ; } &>> output/pud_leak; done