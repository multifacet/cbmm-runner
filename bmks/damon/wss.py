#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0

"Print out the distribution of the working set sizes of the given trace"

import argparse
import struct
import sys
import tempfile

import _dist
import _recfile

def set_argparser(parser):
    parser.add_argument('--input', '-i', type=str, metavar='<file>',
            default='damon.data', help='input file name')
    parser.add_argument('--range', '-r', type=int, nargs=3,
            metavar=('<start>', '<stop>', '<step>'),
            help='range of wss percentiles to print')
    parser.add_argument('--sortby', '-s', choices=['time', 'size'],
            help='the metric to be used for the sort of the working set sizes')
    parser.add_argument('--plot', '-p', type=str, metavar='<file>',
            help='plot the distribution to an image file')

def main(args=None):
    if not args:
        parser = argparse.ArgumentParser()
        set_argparser(parser)
        args = parser.parse_args()

    percentiles = [0, 25, 50, 75, 100]

    file_path = args.input
    if args.range:
        percentiles = range(args.range[0], args.range[1], args.range[2])
    wss_sort = True
    if args.sortby == 'time':
        wss_sort = False

    pid_pattern_map = {}
    with open(file_path, 'rb') as f:
        _recfile.set_fmt_version(f)
        start_time = None
        while True:
            timebin = f.read(16)
            if len(timebin) != 16:
                break
            nr_tasks = struct.unpack('I', f.read(4))[0]
            for t in range(nr_tasks):
                pid = _recfile.pid(f)
                if not pid in pid_pattern_map:
                    pid_pattern_map[pid] = []
                pid_pattern_map[pid].append(_dist.access_patterns(f))

    orig_stdout = sys.stdout
    if args.plot:
        tmp_path = tempfile.mkstemp()[1]
        tmp_file = open(tmp_path, 'w')
        sys.stdout = tmp_file

    print('# <percentile> <wss>')
    for pid in pid_pattern_map.keys():
        # Skip first 20 snapshots as regions may not adjusted yet.
        snapshots = pid_pattern_map[pid][20:]
        wss_dist = []
        for snapshot in snapshots:
            wss = 0
            for p in snapshot:
                # Ignore regions not accessed
                if p[1] <= 0:
                    continue
                wss += p[0]
            wss_dist.append(wss)
        if wss_sort:
            wss_dist.sort(reverse=False)

        print('# pid\t%s' % pid)
        print('# avr:\t%d' % (sum(wss_dist) / len(wss_dist)))
        for percentile in percentiles:
            thres_idx = int(percentile / 100.0 * len(wss_dist))
            if thres_idx == len(wss_dist):
                thres_idx -= 1
            threshold = wss_dist[thres_idx]
            print('%d\t%d' % (percentile, wss_dist[thres_idx]))

    if args.plot:
        sys.stdout = orig_stdout
        tmp_file.flush()
        tmp_file.close()
        xlabel = 'runtime (percent)'
        if wss_sort:
            xlabel = 'percentile'
        _dist.plot_dist(tmp_path, args.plot, xlabel,
                'working set size (bytes)')

if __name__ == '__main__':
    main()
