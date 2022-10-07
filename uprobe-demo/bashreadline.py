from bcc import BPF
from time import strftime

# load the bpf program
b = BPF(src_file = "bashreadline.c", cflags = ["-Wno-macro-redefined"])

# attach bpf program to the uretprobe
b.attach_uretprobe(name = "/usr/bin/bash", sym = "readline", fn_name = "bash_read")

# define perf event callback function
def print_event(cpu, data, size):
    event = b['events'].event(data)
    print("%-9s %-6d %s" % (strftime("%H:%M:%S"), event.uid, event.command.decode("utf-8")))

# print header
print("%-9s %-6s %s" % ("TIME", "UID", "COMMAND"))

# binding output function to perf events and polling data from the map
b['events'].open_perf_buffer(print_event)
while 1:
    try:
        b.perf_buffer_poll()
    except KeyboardInterrupt:
        exit()
