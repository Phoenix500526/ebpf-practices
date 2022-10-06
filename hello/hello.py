#!/usr/bin/env python3

# This is a userspace program

# step 1: import bcc library
from bcc import BPF

# step 2: load BPF program 
bpf_text = BPF(src_file = "hello.c")

# step 3: attach kprobe, fn_name(hello_world) is a function we defined before in the hello.c 
bpf_text.attach_kprobe(event = "do_sys_openat2", fn_name = "hello_world")

# step 4: read and print /sys/kernel/debug/tracing/trace_pipe
bpf_text.trace_print()
