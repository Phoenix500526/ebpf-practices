from bcc import BPF, USDT
import sys

if len(sys.argv) < 2:
    print("Usage: %s <tracee_pid>" % sys.argv[0])
    sys.exit(1)

u = USDT(pid=int(sys.argv[1]))
u.enable_probe(probe = "function__entry", fn_name = "print_functions")
b = BPF(src_file = "python-trace.c", usdt_contexts = [u], cflags = ["-Wno-macro-redefined"])

def print_event(cpu, data, size):
    event = b["events"].event(data)
    print("%-16s %-16s %d" % (event.filename.decode('utf-8'), event.function.decode("utf-8"), event.lineno))

print("%-16s %-16s %s" % ("FILENAME", "FUNCTION", "LINENO"))

b["events"].open_perf_buffer(print_event)
while 1:
    try:
        b.perf_buffer_poll()
    except KeyboardInterrupt:
        exit()