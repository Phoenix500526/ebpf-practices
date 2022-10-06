#!/usr/bin/env python3

# This is a userspace program

# step 1: import bcc library
from bcc import BPF

# step 2: load BPF program. bpf_text is a map, and bpf_text["events"] is 
# what we defined in the trace-open.c via the macro BPF_PERF_OUTPUT
bpf_text = BPF(src_file = "trace-open.c", cflags=["-Wno-macro-redefined"])

# step 3: attach kprobe
bpf_text.attach_kprobe(event = "do_sys_openat2", fn_name = "hello_world")

# step 4: print header
print("%-18s %-16s %-16s %-16s" % ("TIME(s)", "COMM", "PID", "FILE"))

# step 5: define a callback for perf event
start = 0
def print_event(cpu, data, size):
    global start
    event = bpf_text["events"].event(data)
    if start == 0:
        start = event.timestamp
    time_s = (float(event.timestamp - start)) / 1000000000
    print("%-18.9f %-16s %-16d %-16s" % (time_s, event.comm, event.pid, event.fname))


# step 6: loop with callback to print_event
bpf_text["events"].open_perf_buffer(print_event)
while 1:
    try:
        bpf_text.perf_buffer_poll()
    except KeyboardInterrupt:
        exit()