import os
import re
import sys
import glob
import ctypes
import argparse

FUZZER_STATS_RX = re.compile('([a-zA-Z_]+)\s+:\s+(.+?)\n')

def parse_arguments():
    parser = argparse.ArgumentParser()
    parser.add_argument('-s', '--summary', default=False, action='store_true',
                        help='skip all per-fuzzer trivia and show just the \
                        summary results.'
                        )
    parser.add_argument('afl_sync_dir', help='path to afl sync directory')

    args = parser.parse_args()
    return args


def get_cur_time():
    class FileTime(ctypes.Structure):
        _pack_ = 1
        _fields_ = [('dwLowDateTime', ctypes.c_uint32),
                    ('dwHighDateTime', ctypes.c_uint32)]

    file_time = FileTime()
    GetSystemTimeAsFileTime = ctypes.windll.kernel32.GetSystemTimeAsFileTime
    GetSystemTimeAsFileTime(ctypes.byref(file_time))

    ret = (file_time.dwHighDateTime << 32) + file_time.dwLowDateTime

    return ret / 10000000


def is_process_running(pid):
    # not very pythonic, but I didn't want to require external dependencies
    OpenProcess = ctypes.windll.kernel32.OpenProcess
    CloseHandle = ctypes.windll.kernel32.CloseHandle

    SYNCHRONIZE = 0x00100000
    process = OpenProcess(SYNCHRONIZE, False, ctypes.c_uint32(pid))
    if not process:
        return False

    CloseHandle(process)
    return True


def parse_fuzzer_stats(path):
    data = ''
    with open(path, 'rb') as f:
        data = f.read().decode('utf-8')

    stats = dict(FUZZER_STATS_RX.findall(data))

    # parse to int / float
    for key, value in stats.items():
        if not value.isdecimal():
            continue

        if not value.isnumeric():
            stats[key] = float(value)
            continue

        stats[key] = int(value)

    return stats


def main():
    args = parse_arguments()

    if not os.path.isdir(args.afl_sync_dir):
        print("error: {} is not a directory".format(args.afl_sync_dir))
        return 1

    if os.path.isdir(os.path.join(args.afl_sync_dir, 'queue')):
        print("[-] Error: parameter is an individual output directory, not a sync dir.")
        return 1

    print("status check tool for afl-fuzz by <lcamtuf@google.com>\n")

    verbose = not args.summary

    # stats for all fuzzers
    alive_count = 0
    dead_count = 0
    total_time = 0
    total_execs = 0
    total_eps = 0
    total_crashes = 0
    total_pfav = 0
    total_pending = 0

    if verbose:
        print("Individual fuzzers")
        print("==================\n")

    fuzzer_stats_path = os.path.join(args.afl_sync_dir, '*', 'fuzzer_stats')
    for stats_path in glob.glob(fuzzer_stats_path):
        try:
            stats = parse_fuzzer_stats(stats_path)

            start_time = stats['start_time']
            run_time = get_cur_time() - start_time
            run_days = int(((run_time / 60) / 60) / 24)
            run_hours = int((run_time / 60 / 60) % 24)

            if verbose:
                print(">>> {} ({} days, {} hours) <<<\n".
                      format(stats['afl_banner'], run_days, run_hours))

            if not is_process_running(stats['fuzzer_pid']):
                if verbose:
                    print("  Instance is dead_count or running remotely, skipping.\n")
                dead_count += 1
                continue

            alive_count += 1
            execs_done = stats['execs_done']
            exec_sec = float(execs_done) / run_time
            path_percent = (float(stats['cur_path']) * 100) / stats['paths_total']

            total_time += run_time
            total_eps += exec_sec
            total_execs += execs_done
            total_crashes += stats['unique_crashes']
            total_pending += stats['pending_total']
            total_pfav += stats['pending_favs']

            if verbose:
                print("  cycle {}, lifetime speed {:.2f} exec/sec, path {}/{} {:.2f}%".
                      format(stats['cycles_done'], exec_sec, stats['cur_path'],
                             stats['paths_total'], path_percent))

                if stats['unique_crashes'] == 0:
                    print("  pending {}/{}, coverage {}, no crashes yet".
                          format(stats['pending_favs'], stats['pending_total'],
                                 stats['bitmap_cvg']))
                else:
                    print("  pending {}/{}, coverage {}, crash count {} (!)".
                          format(stats['pending_favs'], stats['pending_total'],
                                 stats['bitmap_cvg'], stats['unique_crashes']))

                print("")
        except:
            print("error in parsing fuzzer_stat: {}, seems to be corrupt?".format(stats_path))
            continue

    total_days = int(total_time / 60 / 60 / 24)
    total_hours = int((total_time / 60 / 60) % 24)

    print("Summary stats")
    print("=============")
    print("")

    print("       Fuzzers alive : {}".format(alive_count))

    if dead_count > 0:
        print("      Dead or remote : {} (excluded from stats)".format(dead_count))

    print("      Total run time : {} days, {} hours".format(total_days, total_hours))
    print("         Total execs : {} million".format(int(total_execs / 1000 / 1000)))
    print("    Cumulative speed : {:.2f} execs/sec".format(total_eps))
    print("       Pending paths : {} faves, {} total".format(total_pfav, total_pending))
    if alive_count > 0:
        print("  Pending per fuzzer : {:.2f} faves, {:.2f} total (on average)".
              format(total_pfav / float(alive_count),
                     total_pending / float(alive_count)))

        print("       Crashes found : {} locally unique".format(total_crashes))

    print("")

    return 0


if __name__ == '__main__':
    sys.exit(main())
