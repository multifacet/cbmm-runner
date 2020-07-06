#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0

"""
Record data access patterns of the target process.
"""

import argparse
import os
import signal
import subprocess
import time

import _damon

def do_record(target, is_target_cmd, init_regions, attrs, old_attrs, wait):
    if os.path.isfile(attrs.rfile_path):
        os.rename(attrs.rfile_path, attrs.rfile_path + '.old')

    if attrs.apply():
        print('attributes (%s) failed to be applied' % attrs)
        cleanup_exit(old_attrs, -1)
    print('# damon attrs: %s %s' % (attrs.attr_str(), attrs.record_str()))
    if is_target_cmd:
        p = subprocess.Popen(target, shell=True, executable='/bin/bash')
        target = p.pid
    if _damon.set_target(target, init_regions):
        print('target setting (%s, %s) failed' % (target, init_regions))
        cleanup_exit(old_attrs, -2)
    if _damon.turn_damon('on'):
        print('could not turn on damon' % target)
        cleanup_exit(old_attrs, -3)
    while not _damon.is_damon_running():
        time.sleep(1)
    if is_target_cmd:
        print('Press Ctrl+C to stop')
        p.wait()
    while wait:
        print('Press Ctrl+C to stop')
        # damon will turn it off by itself if the target tasks are terminated.
        if not _damon.is_damon_running():
            break
        time.sleep(1)

    if wait:
        cleanup_exit(old_attrs, 0)

def cleanup_exit(orig_attrs, exit_code):
    if _damon.is_damon_running():
        if _damon.turn_damon('off'):
            print('failed to turn damon off!')
        while _damon.is_damon_running():
            time.sleep(1)
    if orig_attrs:
        if orig_attrs.apply():
            print('original attributes (%s) restoration failed!' % orig_attrs)
    exit(exit_code)

def sighandler(signum, frame):
    print('\nsignal %s received' % signum)
    cleanup_exit(orig_attrs, signum)

def chk_permission():
    if os.geteuid() != 0:
        print("Run as root")
        exit(1)

def set_argparser(parser):
    _damon.set_attrs_argparser(parser)
    _damon.set_init_regions_argparser(parser)
    parser.add_argument('target', type=str, metavar='<target>',
            nargs=argparse.REMAINDER,
            help='the target command or the pid to record')
    parser.add_argument('-l', '--rbuf', metavar='<len>', type=int,
            default=1024*1024, help='length of record result buffer')
    parser.add_argument('-o', '--out', metavar='<file path>', type=str,
            default='damon.data', help='output file path')
    parser.add_argument('-w', '--wait',
            default=False, help='wait for process termination')

def default_paddr_region():
    "Largest System RAM region becomes the default"
    ret = []
    with open('/proc/iomem', 'r') as f:
        # example of the line: '100000000-42b201fff : System RAM'
        for line in f:
            fields = line.split(':')
            if len(fields) != 2:
                continue
            name = fields[1].strip()
            if name != 'System RAM':
                continue
            addrs = fields[0].split('-')
            if len(addrs) != 2:
                continue
            start = int(addrs[0], 16)
            end = int(addrs[1], 16)

            sz_region = end - start
            if not ret or sz_region > (ret[1] - ret[0]):
                ret = [start, end]
    return ret

def main(args=None):
    global orig_attrs
    if not args:
        parser = argparse.ArgumentParser()
        set_argparser(parser)
        args = parser.parse_args()

    chk_permission()
    _damon.chk_update_debugfs(args.debugfs)

    signal.signal(signal.SIGINT, sighandler)
    signal.signal(signal.SIGTERM, sighandler)
    orig_attrs = _damon.current_attrs()

    args.schemes = ''
    new_attrs = _damon.cmd_args_to_attrs(args)
    init_regions = _damon.cmd_args_to_init_regions(args)
    target = args.target
    if target[0] == "--":
        target = target[1:]

    if len(target) == 1 and target[0] == 'paddr':   # physical memory address space
        if not init_regions:
            init_regions = [default_paddr_region()]
        do_record(target, False, init_regions, new_attrs, orig_attrs, args.wait)
    elif not subprocess.call('which %s > /dev/null' % target_fields[0],
            shell=True, executable='/bin/bash'):
        print("Assuming %s is executable" % target)
        do_record(target, True, init_regions, new_attrs, orig_attrs, args.wait)
    else:
        try:
            pid = int(target)
            print("Assuming %s is PID" % target)
        except:
            print('target \'%s\' is neither a command, nor a pid' % target)
            exit(1)
        do_record(target, False, init_regions, new_attrs, orig_attrs, args.wait)

if __name__ == '__main__':
    main()
