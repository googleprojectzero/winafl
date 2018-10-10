import os
import sys
import argparse
import tempfile
import time
import subprocess
import re

FUZZER_STATS_RX = re.compile('([a-zA-Z_]+)\s+:\s+(.+?)\n')

TEMPLATE = '''
<table style="font-family: 'Trebuchet MS', 'Tahoma', 'Arial', 'Helvetica'">
<tr><td style="width: 18ex"><b>Banner:</b></td><td>{banner}</td></tr>
<tr><td><b>Directory:</b></td><td>{fuzzer_dir}</td></tr>
<tr><td><b>Generated on:</b></td><td>{date}</td></tr>
</table>
<p>
<img src="high_freq.png" width=1000 height=300><p>
<img src="low_freq.png" width=1000 height=200><p>
<img src="exec_speed.png" width=1000 height=200>
'''.strip()

GNUPLOT_CMDS = '''
set terminal png truecolor enhanced size 1000,300 butt

set output '{outdir}/high_freq.png'

set xdata time
set timefmt '%s'
set format x "%b %d\\n%H:%M"
set tics font 'small'
unset mxtics
unset mytics

set grid xtics linetype 0 linecolor rgb '#e0e0e0'
set grid ytics linetype 0 linecolor rgb '#e0e0e0'
set border linecolor rgb '#50c0f0'
set tics textcolor rgb '#000000'
set key outside

set autoscale xfixmin
set autoscale xfixmax

plot '{fuzzer_dir}/plot_data' using 1:4 with filledcurve x1 title 'total paths' linecolor rgb '#000000' fillstyle transparent solid 0.2 noborder, \\
     '' using 1:3 with filledcurve x1 title 'current path' linecolor rgb '#f0f0f0' fillstyle transparent solid 0.5 noborder, \\
     '' using 1:5 with lines title 'pending paths' linecolor rgb '#0090ff' linewidth 3, \\
     '' using 1:6 with lines title 'pending favs' linecolor rgb '#c00080' linewidth 3, \\
     '' using 1:2 with lines title 'cycles done' linecolor rgb '#c000f0' linewidth 3

set terminal png truecolor enhanced size 1000,200 butt
set output '{outdir}/low_freq.png'

plot '{fuzzer_dir}/plot_data' using 1:8 with filledcurve x1 title '' linecolor rgb '#c00080' fillstyle transparent solid 0.2 noborder, \\
     '' using 1:8 with lines title ' uniq crashes' linecolor rgb '#c00080' linewidth 3, \\
     '' using 1:9 with lines title 'uniq hangs' linecolor rgb '#c000f0' linewidth 3, \\
     '' using 1:10 with lines title 'levels' linecolor rgb '#0090ff' linewidth 3

set terminal png truecolor enhanced size 1000,200 butt
set output '{outdir}/exec_speed.png'

plot '{fuzzer_dir}/plot_data' using 1:11 with filledcurve x1 title '' linecolor rgb '#0090ff' fillstyle transparent solid 0.2 noborder, \\
     '{fuzzer_dir}/plot_data' using 1:11 with lines title '    execs/sec' linecolor rgb '#0090ff' linewidth 3 smooth bezier;
'''

def parse_arguments():
    parser = argparse.ArgumentParser()
    parser.add_argument('sync_dir', help='sync directory for afl')
    parser.add_argument('out_dir', help='output directory for plot')

    args = parser.parse_args()
    return args


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

    # get banner
    stats_path = os.path.join(args.sync_dir, 'fuzzer_stats')
    stats = parse_fuzzer_stats(stats_path)
    banner = stats['afl_banner']

    # format date in a compatible manner
    date = time.strftime('%a %b %d %H:%M:%S DST %Y', time.localtime())

    try:
        os.makedirs(args.out_dir)
    except OSError:
        pass

    # write html file
    index_html = os.path.join(args.out_dir, 'index.html')
    with open(index_html, 'wb') as f:
        f.write(TEMPLATE.format(outdir=args.out_dir,
                                fuzzer_dir=args.sync_dir,
                                date=date,
                                banner=banner).encode('utf-8'))

    tmp_file = tempfile.NamedTemporaryFile(delete=False)
    tmp_file.write(GNUPLOT_CMDS.format(outdir=args.out_dir,
                                       fuzzer_dir=args.sync_dir).encode('utf-8'))
    tmp_file.flush()

    # run gnuplot
    try:
        subprocess.check_output(['gnuplot', '-c', tmp_file.name])
    except subprocess.CalledProcessError as e:
        print("Error: failed to run gnuplot, output = {}".format(e))
    except OSError:
        print("Error: gnuplot was not found, make sure that gnuplot is installed and in PATH")

    try:
        os.unlink(tmp_file.name)
    except OSError:
        pass


if __name__ == '__main__':
    main()
