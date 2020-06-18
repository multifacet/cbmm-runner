#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0

import argparse
import os
import struct
import sys

import _recfile

def parse_time(bindat):
    "bindat should be 16 bytes"
    sec = struct.unpack('l', bindat[0:8])[0]
    nsec = struct.unpack('l', bindat[8:16])[0]
    return sec * 1000000000 + nsec;

def pr_region(f):
    saddr = struct.unpack('L', f.read(8))[0]
    eaddr = struct.unpack('L', f.read(8))[0]
    nr_accesses = struct.unpack('I', f.read(4))[0]
    print("%012x-%012x(%10d):\t%d" %
            (saddr, eaddr, eaddr - saddr, nr_accesses))

def pr_task_info(f):
    pid = _recfile.pid(f)
    print("pid: ", pid)
    nr_regions = struct.unpack('I', f.read(4))[0]
    print("nr_regions: ", nr_regions)
    for r in range(nr_regions):
        pr_region(f)

def set_argparser(parser):
    parser.add_argument('--input', '-i', type=str, metavar='<file>',
            default='damon.data', help='input file name')

def main(args=None):
    if not args:
        parser = argparse.ArgumentParser()
        set_argparser(parser)
        args = parser.parse_args()

    file_path = args.input

    if not os.path.isfile(file_path):
        print('input file (%s) is not exist' % file_path)
        exit(1)

    with open(file_path, 'rb') as f:
        _recfile.set_fmt_version(f)
        start_time = None
        while True:
            timebin = f.read(16)
            if len(timebin) != 16:
                break
            time = parse_time(timebin)
            if not start_time:
                start_time = time
                print("start_time: ", start_time)
            print("rel time: %16d" % (time - start_time))
            nr_tasks = struct.unpack('I', f.read(4))[0]
            print("nr_tasks: ", nr_tasks)
            for t in range(nr_tasks):
                pr_task_info(f)
                print("")

if __name__ == '__main__':
    main()
