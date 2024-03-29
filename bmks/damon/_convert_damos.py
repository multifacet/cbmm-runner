#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0

"""
Change human readable data access monitoring-based operation schemes to the low
level input for the '<debugfs>/damon/schemes' file.  Below is an example of the
schemes written in the human readable format:

    # format is:
    # <min/max size> <min/max frequency (0-99)> <min/max age> <action>
    #
    # B/K/M/G/T for Bytes/KiB/MiB/GiB/TiB
    # us/ms/s/m/h/d for micro-seconds/milli-seconds/seconds/minutes/hours/days
    # 'null' means zero for size and age.

    # if a region keeps a high access frequency for more than 100ms, put the
    # region on the head of the LRU list (call madvise() with MADV_WILLNEED).
    null    null    80      null    100ms   0s      willneed

    # if a region keeps a low access frequency for more than 200ms and less
    # than one hour, put the # region on the tail of the LRU list (call
    # madvise() with MADV_COLD).
    0B      0B      10      20      200ms   1h cold

    # if a region keeps a very low access frequency for more than 1 minute,
    # swap out the region immediately (call madvise() with MADV_PAGEOUT).
    0B      null    0       10      60s     0s pageout

    # if a region of a size bigger than 2MiB keeps a very high access frequency
    # for more than 100ms, let the region to use huge pages (call madvise()
    # with MADV_HUGEPAGE).
    2M      null    90      99      100ms   0s hugepage

    # If a regions of a size bigger than 2MiB keeps small access frequency for
    # more than 100ms, avoid the region using huge pages (call madvise() with
    # MADV_NOHUGEPAGE).
    2M      null    0       25      100ms   0s nohugepage
"""

import argparse

unit_to_bytes = {'B': 1, 'K': 1024, 'M': 1024 * 1024, 'G': 1024 * 1024 * 1024,
        'T': 1024 * 1024 * 1024 * 1024}

def text_to_bytes(txt):
    if txt == 'null':
        return 0
    unit = txt[-1]
    number = int(txt[:-1])
    return number * unit_to_bytes[unit]

unit_to_usecs = {'us': 1, 'ms': 1000, 's': 1000 * 1000, 'm': 60 * 1000 * 1000,
        'h': 60 * 60 * 1000 * 1000, 'd': 24 * 60 * 60 * 1000 * 1000}

def text_to_us(txt):
    if txt == 'null':
        return 0
    unit = txt[-2:]
    if unit in ['us', 'ms']:
        number = int(txt[:-2])
    else:
        unit = txt[-1]
        number = int(txt[:-1])
    return number * unit_to_usecs[unit]

damos_action_to_int = {'DAMOS_WILLNEED': 0, 'DAMOS_COLD': 1,
        'DAMOS_PAGEOUT': 2, 'DAMOS_HUGEPAGE': 3, 'DAMOS_NOHUGEPAGE': 4,
        'DAMOS_STAT': 5}

def text_to_damos_action(txt):
    return damos_action_to_int['DAMOS_' + txt.upper()]

def text_to_nr_accesses(txt, max_nr_accesses):
    if txt == 'null':
        return 0
    return int(int(txt) * max_nr_accesses / 100)

def debugfs_scheme(line, sample_interval, aggr_interval):
    fields = line.split()
    if len(fields) != 7:
        print('wrong input line: %s' % line)
        exit(1)

    limit_nr_accesses = aggr_interval / sample_interval
    try:
        min_sz = text_to_bytes(fields[0])
        max_sz = text_to_bytes(fields[1])
        min_nr_accesses = text_to_nr_accesses(fields[2], limit_nr_accesses)
        max_nr_accesses = text_to_nr_accesses(fields[3], limit_nr_accesses)
        min_age = text_to_us(fields[4]) / aggr_interval
        max_age = text_to_us(fields[5]) / aggr_interval
        action = text_to_damos_action(fields[6])
    except:
        print('wrong input field')
        raise
    return '%d\t%d\t%d\t%d\t%d\t%d\t%d' % (min_sz, max_sz, min_nr_accesses,
            max_nr_accesses, min_age, max_age, action)

def convert(schemes_file, sample_interval, aggr_interval):
    lines = []
    with open(schemes_file, 'r') as f:
        for line in f:
            if line.startswith('#'):
                continue
            line = line.strip()
            if line == '':
                continue
            lines.append(debugfs_scheme(line, sample_interval, aggr_interval))
    return '\n'.join(lines)

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('input', metavar='<file>',
            help='input file describing the schemes')
    parser.add_argument('-s', '--sample', metavar='<interval>', type=int,
            default=5000, help='sampling interval (us)')
    parser.add_argument('-a', '--aggr', metavar='<interval>', type=int,
            default=100000, help='aggregation interval (us)')
    args = parser.parse_args()

    schemes_file = args.input
    sample_interval = args.sample
    aggr_interval = args.aggr

    print(convert(schemes_file, sample_interval, aggr_interval))

if __name__ == '__main__':
    main()
