#!/usr/bin/env python2

from __future__ import print_function
from bcc import BPF
import argparse
from time import strftime
import sys
import os

parser = argparse.ArgumentParser(description = "Record statistics for each page fault")
parser.add_argument("-t", "--threshold", required=True,
                help="The threshold in NANOSECONDS (== THRESHCYC * 1000 / FREQMHZ)")
args = parser.parse_args()

bpf_text = r"""
#include <uapi/linux/ptrace.h>
#include <bcc/proto.h>
#include <linux/sched.h>

const u64 THRESHOLD = #THRESHOLD_PLACEHOLDER#;

BPF_HASH(currpf, u64, u64);

int kprobe__handle_mm_fault(struct pt_regs *ctx)
{
        u64 pid = bpf_get_current_pid_tgid();
        u64 ts = bpf_ktime_get_ns();

        currpf.update(&pid, &ts);

        return 0;
}

int kretprobe__handle_mm_fault(struct pt_regs *ctx)
{
        u64 pid = bpf_get_current_pid_tgid();
        u64 end = bpf_ktime_get_ns();

        u64 *start = currpf.lookup(&pid);
        if (start == 0) {
                return 0;
        }

        u64 lat = end - *start;
        bpf_trace_printk("bpfpftrace %lld\n", lat);

        currpf.delete(&pid);

        return 0;
}

// Not-anonymous page
int do_fault_probe(struct pt_regs *ctx)
{
        u64 pid = bpf_get_current_pid_tgid();
        currpf.delete(&pid);

        return 0;
}

int kprobe__do_swap_page(struct pt_regs *ctx)
{
        u64 pid = bpf_get_current_pid_tgid();
        currpf.delete(&pid);

        return 0;
}
"""

# Do some fancy code substitution
bpf_text = bpf_text.replace("#THRESHOLD_PLACEHOLDER#", args.threshold)
b = BPF(text=bpf_text)
b.attach_kprobe(event="__do_fault.isra.61", fn_name="do_fault_probe")

THRESHOLD = int(args.threshold)
FAST_COUNT = 0

while not os.path.isfile("/tmp/stop-pf-bpf"):
    # Read messages from kernel pipe
    try:
        (task, pid, cpu, flags, ts, msg) = b.trace_fields()
        (tag, latency) = msg.split()
    except ValueError:
        # Ignore messages from other tracers
        continue

    if not tag == "bpfpftrace":
        continue

    if int(latency) < THRESHOLD:
        FAST_COUNT += 1
    else:
        print(latency)

print("fast: %d" % FAST_COUNT)

print("BPFPFTRACE DONE", file=sys.stderr)
