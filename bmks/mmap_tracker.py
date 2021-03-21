#!/usr/bin/python3
from bcc import BPF
import argparse
from time import strftime

parser = argparse.ArgumentParser(description = "Record statistics for each mmap call")
parser.add_argument("-p", "--pid", help="PID of the process to track")
parser.add_argument("--ebpf", action="store_true", help="Print the eBPF script")
args = parser.parse_args()

bpf_text = """
#include <linux/sched.h>
#include <uapi/linux/ptrace.h>
#include <bcc/proto.h>

BPF_PERF_OUTPUT(mmap_events);

struct mmap_info_t {
    unsigned long addr;
    unsigned long len;
    unsigned long prot;
    unsigned long flags;
    long fd;
    unsigned long off;
    u32 pid;
    u32 tid;
    char comm[TASK_COMM_LEN];
};

TRACEPOINT_PROBE(syscalls, sys_enter_mmap) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u32 tid = bpf_get_current_pid_tgid() & 0xFFFFFFFF;
    if(FILTER_PID)
        return 0;

    struct mmap_info_t info = {};
    info.addr = args->addr;
    info.len = args->len;
    info.prot = args->prot;
    info.flags = args->flags;
    info.fd = args->fd;
    info.off = args->off;
    info.pid = pid;
    info.tid = tid;
    bpf_get_current_comm(&info.comm, sizeof(info.comm));

    mmap_events.perf_submit(args, &info, sizeof(info));

    return 0;
}

"""

# Do some fancy code substitution
if args.pid:
    bpf_text = bpf_text.replace("FILTER_PID", "(pid != %s)" % args.pid)
else:
    bpf_text = bpf_text.replace("FILTER_PID", "0")

if args.ebpf:
    print(bpf_text)
    exit()

b = BPF(text=bpf_text)

header_string = "%-10.10s %-6s %-6s %-12s %-8s %-8s %-8s %-8s %-8s"
format_string = "%-10.10s %-6d %-6d %-12x %-8x %-8x %-8x %-8d %-8x"
print(header_string % ("COMM", "PID", "TID", "ADDR", "LEN", "PROT",
        "FLAGS", "FD", "OFF"))

def handle_mmap_event(cpu, data, size):
    event = b["mmap_events"].event(data)

    # For some reason, event.fd isn't being sign extended of something
    # because without this, event.fd shows up as 4294967295 when it should
    # be -1
    if event.fd == 4294967295:
        fd = -1
    else:
        fd = event.fd

    print(format_string % (event.comm, event.pid, event.tid, event.addr,
        event.len, event.prot, event.flags, fd, event.off))

b["mmap_events"].open_perf_buffer(handle_mmap_event)

while 1:
    try:
        b.perf_buffer_poll()
    except KeyboardInterrupt:
        print()
        exit()
