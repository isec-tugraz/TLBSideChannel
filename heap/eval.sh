#!/usr/bin/env bash

for i in {1..100}; do echo $i; { sleep 1; time ./cred_leak.elf ; } &>> output/cred_leak; done
for i in {1..100}; do echo $i; { sleep 1; time ./file_leak.elf ; } &>> output/file_leak; done
for i in {1..100}; do echo $i; { sleep 1; time ./msg_msg_leak.elf ; } &>> output/msg_msg_leak; done
for i in {1..100}; do echo $i; { sleep 1; time ./pipe_buffer_leak.elf ; } &>> output/pipe_buffer_leak; done
for i in {1..100}; do echo $i; { sleep 1; time ./seq_file_leak.elf ; } &>> output/seq_file_leak; done
