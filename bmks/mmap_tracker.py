#!/usr/bin/python2
from bcc import BPF
import argparse
from time import strftime
import sys

parser = argparse.ArgumentParser(description = "Record statistics for each mmap call")
parser.add_argument("-c", "--comm", help="The name of the process to track")
parser.add_argument("--ebpf", action="store_true", help="Print the eBPF script")
args = parser.parse_args()

bpf_text = """
#include <linux/sched.h>
#include <uapi/linux/ptrace.h>
#include <bcc/proto.h>

struct mmap_info_t {
    unsigned long addr;
    unsigned long ret_addr;
    unsigned long len;
    unsigned long prot;
    unsigned long flags;
    long fd;
    unsigned long off;
    u32 pid;
    u32 tid;
    char comm[TASK_COMM_LEN];
};

BPF_HASH(maps, u64, struct mmap_info_t);
BPF_PERF_OUTPUT(mmap_events);

static bool strequals(char *s1, char *s2, u32 len) {
    for (u32 i = 0; i < len; i++) {
        if (s1[i] != s2[i]) {
            return false;
        }

        if (s1[i] == '\\0') {
            return true;
        }
    }

    // For whatever reason, the BPF validator complains if this isn't here
    for (u32 i = 0; i < 2; i++){}

    return true;
}

TRACEPOINT_PROBE(syscalls, sys_enter_mmap) {
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 pid = pid_tgid >> 32;
    u32 tid = pid_tgid & 0xFFFFFFFF;
    char comm[TASK_COMM_LEN];
    char target[TASK_COMM_LEN] = "TARGET_COMM";

    bpf_get_current_comm(&comm, sizeof(comm));
    if(FILTER_PID)
        return 0;

    struct mmap_info_t info = {};
    info.addr = args->addr;
    info.ret_addr = 0;
    info.len = args->len;
    info.prot = args->prot;
    info.flags = args->flags;
    info.fd = args->fd;
    info.off = args->off;
    info.pid = pid;
    info.tid = tid;
    bpf_get_current_comm(&info.comm, sizeof(info.comm));

    maps.update(&pid_tgid, &info);

    return 0;
}

TRACEPOINT_PROBE(syscalls, sys_exit_mmap) {
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 pid = pid_tgid >> 32;
    char comm[TASK_COMM_LEN];
    char target[TASK_COMM_LEN] = "TARGET_COMM";

    bpf_get_current_comm(&comm, sizeof(comm));
    if(FILTER_PID)
        return 0;

    struct mmap_info_t *info;
    info = maps.lookup(&pid_tgid);
    if (info == 0)
        return 0;

    info->ret_addr = args->ret;
    mmap_events.perf_submit(args, info, sizeof(*info));

    maps.delete(&pid_tgid);

    return 0;
}

"""

# Do some fancy code substitution
if args.comm:
    if len(args.comm) > 16:
        args.comm = args.comm[0:15]

    bpf_text = bpf_text.replace("TARGET_COMM", args.comm)
    bpf_text = bpf_text.replace("FILTER_PID", "!strequals(comm, target, TASK_COMM_LEN)" )
else:
    bpf_text = bpf_text.replace("FILTER_PID", "0")

if args.ebpf:
    print(bpf_text)
    exit()

b = BPF(text=bpf_text)

header_string = "%-10.10s %-6s %-6s %-14s %-14s %-10s %-10s %-10s %-8s %-10s"
format_string = "%-10.10s %-6d %-6d 0x%-12x 0x%-12x 0x%-8x 0x%-8x 0x%-8x %-8d 0x%-8x"
print(header_string % ("COMM", "PID", "TID", "ADDR", "RETADDR", "LEN", "PROT",
        "FLAGS", "FD", "OFF"))

def handle_mmap_event(cpu, data, size):
    event = b["mmap_events"].event(data)

    # For some reason, event.fd isn't being sign extended or something
    # because without this, event.fd shows up as 4294967295 when it should
    # be -1
    if event.fd == 4294967295:
        fd = -1
    else:
        fd = event.fd

    print(format_string % (event.comm, event.pid, event.tid, event.addr, event.ret_addr,
        event.len, event.prot, event.flags, fd, event.off))
    sys.stdout.flush()

b["mmap_events"].open_perf_buffer(handle_mmap_event)

while 1:
    try:
        b.perf_buffer_poll()
    except KeyboardInterrupt:
        print()
        exit()
