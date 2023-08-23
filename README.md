# WinAFL

```
   Original AFL code written by Michal Zalewski <lcamtuf@google.com>

   Windows fork written and maintained by Ivan Fratric <ifratric@google.com>

   Copyright 2016 Google Inc. All Rights Reserved.

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at

       http://www.apache.org/licenses/LICENSE-2.0

   Unless required by applicable law or agreed to in writing, software
   distributed under the License is distributed on an "AS IS" BASIS,
   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
   See the License for the specific language governing permissions and
   limitations under the License.
```

## Background

AFL is a popular fuzzing tool for coverage-guided fuzzing. The tool combines
fast target execution with clever heuristics to find new execution paths in
the target binary. It has been successfully used to find a large number of
vulnerabilities in real products. For more info about the original project,
please refer to the original documentation at:

http://lcamtuf.coredump.cx/afl/

Unfortunately, the original AFL does not work on Windows due to very
*nix-specific design (e.g. instrumentation, forkserver etc.). This project is
a fork of AFL that uses different instrumentation approach which works on
Windows even for black box binary fuzzing.

## The WinAFL approach

Instead of instrumenting the code at compilation time, WinAFL supports the
following instrumentation modes:
 - Dynamic instrumentation using DynamoRIO (http://dynamorio.org/)
 - Dynamic instrumentation using TinyInst (https://github.com/googleprojectzero/TinyInst)
 - Hardware tracing using Intel PT
 - Static instrumentation via Syzygy

These instrumentation modes are described in more detail in the separate
documents.

<p align="center">
<img alt="afl-fuzz.exe" src="screenshots/afl-fuzz.gif"/>
</p>

To improve the process startup time, WinAFL relies heavily on persistent
fuzzing mode, that is, executing multiple input samples without restarting the
target process. This is accomplished by selecting a target function (that the
user wants to fuzz) and instrumenting it so that it runs in a loop.

#### Known CVEs

WinAFL has been successfully used to identify bugs in Windows software, such as the following:

| Software | Bugs | Found by |
| - | - | - |
| Adobe | [CVE-2018-4985](https://cpr-zero.checkpoint.com/vulns/cprid-2046/), [CVE-2018-5063](https://cpr-zero.checkpoint.com/vulns/cprid-2047/), [CVE-2018-5064](https://cpr-zero.checkpoint.com/vulns/cprid-2048/), [CVE-2018-5065](https://cpr-zero.checkpoint.com/vulns/cprid-2049/), [CVE-2018-5068](https://cpr-zero.checkpoint.com/vulns/cprid-2050/), [CVE-2018-5069](https://cpr-zero.checkpoint.com/vulns/cprid-2051/), [CVE-2018-5070](https://cpr-zero.checkpoint.com/vulns/cprid-2052/), [CVE-2018-12754](https://cpr-zero.checkpoint.com/vulns/cprid-2053/), [CVE-2018-12755](https://cpr-zero.checkpoint.com/vulns/cprid-2054/), [CVE-2018-12764](https://cpr-zero.checkpoint.com/vulns/cprid-2055/), [CVE-2018-12765](https://cpr-zero.checkpoint.com/vulns/cprid-2056/), [CVE-2018-12766](https://cpr-zero.checkpoint.com/vulns/cprid-2057/), [CVE-2018-12767](https://cpr-zero.checkpoint.com/vulns/cprid-2058/), [CVE-2018-12768](https://cpr-zero.checkpoint.com/vulns/cprid-2059/), [CVE-2018-12839](https://cpr-zero.checkpoint.com/vulns/cprid-2060/), [CVE-2018-12840](https://cpr-zero.checkpoint.com/vulns/cprid-2061/), [CVE-2018-12848](https://cpr-zero.checkpoint.com/vulns/cprid-2062/), [CVE-2018-12849](https://cpr-zero.checkpoint.com/vulns/cprid-2063/), [CVE-2018-12850](https://cpr-zero.checkpoint.com/vulns/cprid-2064/), [CVE-2018-12857](https://cpr-zero.checkpoint.com/vulns/cprid-2065/), [CVE-2018-12859](https://cpr-zero.checkpoint.com/vulns/cprid-2066/), [CVE-2018-12860](https://cpr-zero.checkpoint.com/vulns/cprid-2067/), [CVE-2018-12861](https://cpr-zero.checkpoint.com/vulns/cprid-2068/), [CVE-2018-12862](https://cpr-zero.checkpoint.com/vulns/cprid-2069/), [CVE-2018-12863](https://cpr-zero.checkpoint.com/vulns/cprid-2070/), [CVE-2018-12864](https://cpr-zero.checkpoint.com/vulns/cprid-2071/), [CVE-2018-12865](https://cpr-zero.checkpoint.com/vulns/cprid-2072/), [CVE-2018-12866](https://cpr-zero.checkpoint.com/vulns/cprid-2073/), [CVE-2018-12867](https://cpr-zero.checkpoint.com/vulns/cprid-2074/), [CVE-2018-12869](https://cpr-zero.checkpoint.com/vulns/cprid-2075/), [CVE-2018-12870](https://cpr-zero.checkpoint.com/vulns/cprid-2076/), [CVE-2018-12871](https://cpr-zero.checkpoint.com/vulns/cprid-2077/), [CVE-2018-12872](https://cpr-zero.checkpoint.com/vulns/cprid-2078/), [CVE-2018-12873](https://cpr-zero.checkpoint.com/vulns/cprid-2079/), [CVE-2018-12874](https://cpr-zero.checkpoint.com/vulns/cprid-2080/), [CVE-2018-12875](https://cpr-zero.checkpoint.com/vulns/cprid-2081/), [CVE-2018-15927](https://cpr-zero.checkpoint.com/vulns/cprid-2082/), CVE-2018-15928, [CVE-2018-15929](https://cpr-zero.checkpoint.com/vulns/cprid-2083/), [CVE-2018-15930](https://cpr-zero.checkpoint.com/vulns/cprid-2084/), [CVE-2018-15931](https://cpr-zero.checkpoint.com/vulns/cprid-2085/), [CVE-2018-15932](https://cpr-zero.checkpoint.com/vulns/cprid-2086/), [CVE-2018-15933](https://cpr-zero.checkpoint.com/vulns/cprid-2087/), [CVE-2018-15934](https://cpr-zero.checkpoint.com/vulns/cprid-2088/), [CVE-2018-15935](https://cpr-zero.checkpoint.com/vulns/cprid-2089/), [CVE-2018-15936](https://cpr-zero.checkpoint.com/vulns/cprid-2090/), [CVE-2018-15937](https://cpr-zero.checkpoint.com/vulns/cprid-2091/), [CVE-2018-15938](https://cpr-zero.checkpoint.com/vulns/cprid-2092/), [CVE-2018-15952](https://cpr-zero.checkpoint.com/vulns/cprid-2093/), [CVE-2018-15953](https://cpr-zero.checkpoint.com/vulns/cprid-2094/), [CVE-2018-15954](https://cpr-zero.checkpoint.com/vulns/cprid-2095/), [CVE-2018-15955](https://cpr-zero.checkpoint.com/vulns/cprid-2096/), [CVE-2018-15956](https://cpr-zero.checkpoint.com/vulns/cprid-2097/) | Yoav Alon ([@yoavalon](https://twitter.com/yoavalon)) and Netanel Ben-Simon ([@NetanelBenSimon](https://twitter.com/netanelbensimon)) of Check Point Software Technologies
| Adobe | CVE-2018-12853, CVE-2018-16024, CVE-2018-16023, CVE-2018-15995 | Guy Inbar ([@guyio_](https://twitter.com/guyio_))
| Adobe | CVE-2018-16004, CVE-2018-16005, CVE-2018-16007, CVE-2018-16009, CVE-2018-16010, CVE-2018-16043, CVE-2018-16045, CVE-2018-16046, CVE-2018-19719, CVE-2018-19720, CVE-2019-7045 | Sebastian Apelt ([@bitshifter123](https://twitter.com/bitshifter123))
| Microsoft | [CVE-2016-7212](https://msrc.microsoft.com/update-guide/en-US/vulnerability/CVE-2016-7212) | Aral Yaman of Noser Engineering AG
| Microsoft | [CVE-2017-0073](https://msrc.microsoft.com/update-guide/en-US/vulnerability/CVE-2017-0073), [CVE-2017-0190](https://msrc.microsoft.com/update-guide/en-US/vulnerability/CVE-2017-0190), [CVE-2017-11816](https://msrc.microsoft.com/update-guide/en-US/vulnerability/CVE-2017-11816), [CVE-2018-8472](https://msrc.microsoft.com/update-guide/en-US/vulnerability/CVE-2018-8472), [CVE-2019-1311](https://msrc.microsoft.com/update-guide/en-US/vulnerability/CVE-2019-1311) | Symeon Paraschoudis ([@symeonp](https://twitter.com/symeonp))
| Microsoft | [CVE-2018-8494](https://msrc.microsoft.com/update-guide/en-US/vulnerability/CVE-2018-8494) | Guy Inbar ([@guyio_](https://twitter.com/guyio_))
| Microsoft | [CVE-2018-8464](https://cpr-zero.checkpoint.com/vulns/cprid-2098/) | Yoav Alon ([@yoavalon](https://twitter.com/yoavalon)) and Netanel Ben-Simon ([@NetanelBenSimon](https://twitter.com/netanelbensimon)) of Check Point Research
| Microsoft | [CVE-2019-0538](https://msrc.microsoft.com/update-guide/en-US/vulnerability/CVE-2019-0538), [CVE-2019-0576](https://msrc.microsoft.com/update-guide/en-US/vulnerability/CVE-2019-0576), [CVE-2019-0577](https://msrc.microsoft.com/update-guide/en-US/vulnerability/CVE-2019-0577), [CVE-2019-0579](https://msrc.microsoft.com/update-guide/en-US/vulnerability/CVE-2019-0579), [CVE-2019-0580](https://msrc.microsoft.com/update-guide/en-US/vulnerability/CVE-2019-0580), [CVE-2019-0879](https://msrc.microsoft.com/update-guide/en-US/vulnerability/CVE-2019-0879), [CVE-2019-0889](https://msrc.microsoft.com/update-guide/en-US/vulnerability/CVE-2019-0889), [CVE-2019-0891](https://msrc.microsoft.com/update-guide/en-US/vulnerability/CVE-2019-0891), [CVE-2019-0899](https://msrc.microsoft.com/update-guide/en-US/vulnerability/CVE-2019-0899), [CVE-2019-0902](https://msrc.microsoft.com/update-guide/en-US/vulnerability/CVE-2019-0902), [CVE-2019-1243](https://msrc.microsoft.com/update-guide/en-US/vulnerability/CVE-2019-1243), [CVE-2019-1250](https://msrc.microsoft.com/update-guide/en-US/vulnerability/CVE-2019-1250), [CVE-2020-0687](https://msrc.microsoft.com/update-guide/en-US/vulnerability/CVE-2020-0687), [CVE-2020-0744](https://msrc.microsoft.com/update-guide/en-US/vulnerability/CVE-2020-0744), [CVE-2020-0879](https://msrc.microsoft.com/update-guide/en-US/vulnerability/CVE-2020-0879), [CVE-2020-0964](https://msrc.microsoft.com/update-guide/en-US/vulnerability/CVE-2020-0964), [CVE-2020-0995](https://msrc.microsoft.com/update-guide/en-US/vulnerability/CVE-2020-0995), [CVE-2020-1141](https://msrc.microsoft.com/update-guide/en-US/vulnerability/CVE-2020-1141), [CVE-2020-1145](https://msrc.microsoft.com/update-guide/en-US/vulnerability/CVE-2020-1145), [CVE-2020-1160](https://msrc.microsoft.com/update-guide/en-US/vulnerability/CVE-2020-1160), [CVE-2020-1179](https://msrc.microsoft.com/update-guide/en-US/vulnerability/CVE-2020-1179), [CVE-2021-1665](https://www.mcafee.com/blogs/other-blogs/mcafee-labs/analyzing-cve-2021-1665-remote-code-execution-vulnerability-in-windows-gdi/) | Hardik Shah ([@hardik05](https://twitter.com/hardik05)) of McAfee
| Microsoft | [CVE-2021-42276](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2021-42276), [CVE-2021-28350](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2021-28350), [CVE-2021-28349](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2021-28349), [CVE-2021-28348](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2021-28348) | Simon Barsky ([expend20](https://twitter.com/expend20))
| Microsoft | [CVE-2022-21903](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2022-21903), [CVE-2022-21904](https://www.seljan.hu/posts/out-of-bounds-read-information-disclosure-vulnerability-in-microsoft-windows-gdi-emr_setdibitstodevice-record/), [CVE-2022-21915](https://www.seljan.hu/posts/out-of-bounds-read-information-disclosure-vulnerability-in-microsoft-windows-gdi-emr_stretchdibits-record/), [CVE-2022-26934](https://www.seljan.hu/posts/out-of-bounds-read-information-disclosure-vulnerability-in-microsoft-windows-gdi-emr_createdibpatternbrushpt-record/), [CVE-2022-29112](https://www.seljan.hu/posts/out-of-bounds-read-information-disclosure-vulnerability-in-microsoft-windows-gdi-emr_bitblt-record/), [CVE-2022-35837](https://www.seljan.hu/posts/arbitrary-read-information-disclosure-vulnerability-in-microsoft-windows-gdi-emr_startdoc-record/), [CVE-2022-34728](https://www.seljan.hu/posts/out-of-bounds-read-information-disclosure-vulnerability-in-microsoft-windows-gdi-emr_setpixelv-record/), [CVE-2022-38006](https://www.seljan.hu/posts/out-of-bounds-read-information-disclosure-vulnerability-in-microsoft-windows-gdi-emr_stretchdibits-record-again/) | [Gábor Selján](https://twitter.com/GaborSeljan)
| Microsoft | [CVE-2021-38665](https://thalium.github.io/blog/posts/leaking-aslr-through-rdp-printer-cache-registry/), [CVE-2021-38666](https://thalium.github.io/blog/posts/deserialization-bug-through-rdp-smart-card-extension/) | Valentino Ricotta with Thalium
| Microsoft | [CVE-2022-26929](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2022-26929), [CVE-2022-30130](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2022-30130) | Eran Zimmerman Gonen ([@3r4nz](https://twitter.com/3r4nz))
| FreeRDP | [CVE-2021-37594](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-37594), [CVE-2021-37595](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-37595) | Valentino Ricotta with Thalium
| Kollective | CVE-2018-11672 | Maksim Shudrak ([@MShudrak](https://twitter.com/MShudrak)) of Salesforce
| Mozilla | [CVE-2018-5177](https://bugzilla.mozilla.org/show_bug.cgi?id=1451908) | Guy Inbar ([@guyio_](https://twitter.com/guyio_))
| libxml2 | CVE-2018-14404 | Guy Inbar ([@guyio_](https://twitter.com/guyio_))
| WinRAR | [CVE-2018-20250, CVE-2018-20251, CVE-2018-20252, CVE-2018-20253](https://research.checkpoint.com/2019/extracting-code-execution-from-winrar/) | Nadav Grossman ([@NadavGrossman](https://twitter.com/NadavGrossman)) of Check Point Software Technologies
| XnView | [CVE-2019-13083](https://github.com/apriorit/pentesting/blob/master/bugs/xnview/0x384e2a.md), [CVE-2019-13084](https://github.com/apriorit/pentesting/blob/master/bugs/xnview/0x26b739.md), [CVE-2019-13085](https://github.com/apriorit/pentesting/blob/master/bugs/xnview/0x30ecfa.md), [CVE-2019-13253](https://github.com/apriorit/pentesting/blob/master/bugs/xnview/0x0000000000385474.md), [CVE-2019-13254](https://github.com/apriorit/pentesting/blob/master/bugs/xnview/0x000000000032e808.md), [CVE-2019-13255](https://github.com/apriorit/pentesting/blob/master/bugs/xnview/0x0000000000327464.md), [CVE-2019-13256](https://github.com/apriorit/pentesting/blob/master/bugs/xnview/0x000000000032e849.md), [CVE-2019-13257](https://github.com/apriorit/pentesting/blob/master/bugs/xnview/0x00000000003273aa.md), [CVE-2019-13258](https://github.com/apriorit/pentesting/blob/master/bugs/xnview/0x0000000000328165.md), [CVE-2019-13259](https://github.com/apriorit/pentesting/blob/master/bugs/xnview/0x000000000032e566.md), [CVE-2019-13260](https://github.com/apriorit/pentesting/blob/master/bugs/xnview/0x0000000000327a07.md), [CVE-2019-13261](https://github.com/apriorit/pentesting/blob/master/bugs/xnview/0x0000000000328384.md), [CVE-2019-13262](https://github.com/apriorit/pentesting/blob/master/bugs/xnview/0x00000000003283eb.md) | [@expend20](https://twitter.com/expend20) and Anton Kukoba of Apriorit
| IrfanView | [CVE-2019-13242](https://github.com/apriorit/pentesting/blob/master/bugs/irfanview/0x0000000000013a98.md), [CVE-2019-13243](https://github.com/apriorit/pentesting/blob/master/bugs/irfanview/0x00000000000249c6.md) | [@expend20](https://twitter.com/expend20) and Anton Kukoba of Apriorit
| FastStone | [CVE-2019-13244](https://github.com/apriorit/pentesting/blob/master/bugs/fsview/0x0000000000002d7d.md), [CVE-2019-13245](https://github.com/apriorit/pentesting/blob/master/bugs/fsview/0x00000000001a95b1.md), [CVE-2019-13246](https://github.com/apriorit/pentesting/blob/master/bugs/fsview/0x00000000001a9601.md) | [@expend20](https://twitter.com/expend20) and Anton Kukoba of Apriorit
| ACDSee | [CVE-2019-13247](https://github.com/apriorit/pentesting/blob/master/bugs/acdsee/0x00000000000024ed.md), [CVE-2019-13248](https://github.com/apriorit/pentesting/blob/master/bugs/acdsee/0x0000000000002450.md), [CVE-2019-13249](https://github.com/apriorit/pentesting/blob/master/bugs/acdsee/0x00000000000b9e7a.md), [CVE-2019-13250](https://github.com/apriorit/pentesting/blob/master/bugs/acdsee/0x00000000000b9c2f.md), [CVE-2019-13251](https://github.com/apriorit/pentesting/blob/master/bugs/acdsee/0x00000000000c47ff.md), [CVE-2019-13252](https://github.com/apriorit/pentesting/blob/master/bugs/acdsee/0x00000000001172b0.md), [CVE-2019-15293](https://www.apriorit.com/dev-blog/640-qa-fuzzing-for-closed-source-windows-software) | [@expend20](https://twitter.com/expend20) and Anton Kukoba of Apriorit
| Foxit | [CVE-2019-13330](https://www.zerodayinitiative.com/advisories/ZDI-19-853/), [CVE-2019-13331](https://www.zerodayinitiative.com/advisories/ZDI-19-854/), [CVE-2020-8844](https://www.zerodayinitiative.com/advisories/ZDI-20-200/) | Natnael Samson ([@NattiSamson](https://twitter.com/NattiSamson))
| Rockwell Automation | [CVE-2020-12034, CVE-2020-12038](https://www.us-cert.gov/ics/advisories/icsa-20-140-01) | [Sharon Brizinov](https://sharonbrizinov.com/) and Amir Preminger of Claroty
| F-Secure & WithSecure | CVE-2021-33599, CVE-2021-33602, CVE-2021-40836, CVE-2021-40837, CVE-2022-28875, CVE-2022-28876, CVE-2022-28879, CVE-2022-28881, CVE-2022-28882, CVE-2022-28883, CVE-2022-28884, CVE-2022-28886, CVE-2022-28887 | [@faty420](https://twitter.com/faty420)

(Let me know if you know of any others, and I'll include them in the list)

## Building WinAFL

1. If you are building with DynamoRIO support, download and build
DynamoRIO sources or download DynamoRIO Windows binary package from
https://github.com/DynamoRIO/dynamorio/releases

2. If you are building with Intel PT support, pull third party dependencies by running `git submodule update --init --recursive` from the WinAFL source directory

3. Open Visual Studio Command Prompt (or Visual Studio x64 Win64 Command Prompt
if you want a 64-bit build). Note that you need a 64-bit winafl.dll build if
you are fuzzing 64-bit targets and vice versa.

4. Go to the directory containing the source

5. Type the following commands. Modify the -DDynamoRIO_DIR flag to point to the
location of your DynamoRIO cmake files (either full path or relative to the
source directory).

### For a 32-bit build:

```
mkdir build32
cd build32
cmake -G"Visual Studio 16 2019" -A Win32 .. -DDynamoRIO_DIR=C:\path\to\DynamoRIO\cmake -DINTELPT=1
cmake --build . --config Release
```

### For a 64-bit build:

```
mkdir build64
cd build64
cmake -G"Visual Studio 16 2019" -A x64 .. -DDynamoRIO_DIR=C:\path\to\DynamoRIO\cmake -DINTELPT=1
cmake --build . --config Release
```

### Build configuration options

The following cmake configuration options are supported:

 - `-DDynamoRIO_DIR=..\path\to\DynamoRIO\cmake` - Needed to build the
   winafl.dll DynamoRIO client

 - `-DTINYINST=1` - Enable TinyInst mode. For more information see
   https://github.com/googleprojectzero/winafl/blob/master/readme_tinyinst.md

 - `-DINTELPT=1` - Enable Intel PT mode. For more information see
   https://github.com/googleprojectzero/winafl/blob/master/readme_pt.md

 - `-DUSE_COLOR=1` - color support (Windows 10 Anniversary edition or higher)

 - `-DUSE_DRSYMS=1` - Drsyms support (use symbols when available to obtain
   -target_offset from -target_method). Enabling this has been known to cause
   issues on Windows 10 v1809, though there are workarounds,
   see https://github.com/googleprojectzero/winafl/issues/145

## Using WinAFL

The command line for afl-fuzz on Windows is different than on Linux. Instead of:

```
%s [ afl options ] -- target_cmd_line
```

it now looks like this:

```
afl-fuzz [afl options] -- [instrumentation options] -- target_cmd_line
```

The following afl-fuzz options are supported:

```
  -i dir        - input directory with test cases
  -o dir        - output directory for fuzzer findings
  -t msec       - timeout for each run
  -s            - deliver sample via shared memory
  -D dir        - directory containing DynamoRIO binaries (drrun, drconfig)
  -w path       - path to winafl.dll
  -e            - expert mode to run WinAFL as a DynamoRIO tool
  -P            - use Intel PT tracing mode
  -Y            - enable the static instrumentation mode
  -f file       - location read by the fuzzed program
  -m limit      - memory limit for the target process
  -p            - persist DynamoRIO cache across target process restarts
  -c cpu        - the CPU to run the fuzzed program
  -d            - quick & dirty mode (skips deterministic steps)
  -n            - fuzz without instrumentation (dumb mode)
  -x dir        - optional fuzzer dictionary
  -I msec       - timeout for process initialization and first run
  -T text       - text banner to show on the screen
  -M \\ -S id   - distributed mode
  -C            - crash exploration mode (the peruvian rabbit thing)
  -l path       - a path to user-defined DLL for custom test cases processing
  -A module     - a module identifying a unique process to attach to
```

Please refer to the original AFL documentation for more info on these flags.

To see the supported instrumentation flags, please refer to the documentation
on the specific instrumentation mode you are interested in (see "Instrumentation modes" below).

## How does my target run under WinAFL

When you select a target function and fuzz an application the following happens:

1. Your target runs normally until your target function is reached.
2. WinAFL starts recording coverage
3. Your target function runs until return
4. WinAFL reports coverage, rewrites the input file and patches EIP
   so that the execution jumps back to step 2
5. After your target function runs for the specified number of iterations,
   the target process is killed and restarted. Note that anything that runs
   after the target function returns is never reached.

## How to select a target function

The target function should do these things during its lifetime:

1. Open the input file. This needs to happen within the target function so
   that you can read a new input file for each iteration as the input file is
   rewritten between target function runs.
2. Parse it (so that you can measure coverage of file parsing)
3. Close the input file. This is important because if the input file is
   not closed WinAFL won't be able to rewrite it.
4. Return normally (So that WinAFL can "catch" this return and redirect
   execution. "returning" via ExitProcess() and such won't work)

## Instrumentation modes

The following documents provide information on using different instrumentation
modes with WinAFL:

 - [Dynamic instrumentation using DynamoRIO](https://github.com/googleprojectzero/winafl/blob/master/readme_dr.md)
 - [Dynamic instrumentation using TinyInst](https://github.com/googleprojectzero/winafl/blob/master/readme_tinyinst.md)
 - [Hardware tracing using Intel PT](https://github.com/googleprojectzero/winafl/blob/master/readme_pt.md)
 - [Static instrumentation via Syzygy](https://github.com/googleprojectzero/winafl/blob/master/readme_syzygy.md)

Before using WinAFL for the first time, you should read the documentation for
the specific instrumentation mode you are interested in. These also contain
usage examples.

## Attaching to a running process

The DynamoRIO instrumentation mode supports dynamically attaching to running processes. This option can be used to fuzz processes that cannot be directly launched by WinAFL, such as system services.

To use it, specify the `-A <module>` option to `afl-fuzz.exe`, where `<module>` is the name of a module loaded only by the target process (if the module is loaded by more than one process WinAFL will terminate).

WinAFL will attach to the target process, and fuzz it normally. When the target process terminates (regardless of the reason), WinAFL will not restart it, but simply try to reattach. It is assumed that the target process will be restarted by an external script (or by the system itself). If WinAFL will not find the new target process within 10 seconds, it will terminate.

## Sample delivery via shared memory

WinAFL supports delivering samples via shared memory (as opposed to via a file, which is the default). This can be enabled by giving `-s` option to `afl-fuzz.exe`. Shared memory is faster and can avoid some problems with files (e.g. unable to overwrite the sample file because a target maintains a lock on it). 
If you are using shared memory for sample delivery then you need to make sure that in your harness you specifically read data from shared memory instead of file. Check a simple harness here:

https://github.com/googleprojectzero/Jackalope/blob/6d92931b2cf614699e2a023254d5ee7e20f6e34b/test.cpp#L41  
https://github.com/googleprojectzero/Jackalope/blob/6d92931b2cf614699e2a023254d5ee7e20f6e34b/test.cpp#L111  

## Corpus minimization

WinAFL includes the windows port of afl-cmin in winafl-cmin.py. Please run the
below command to see the options and usage examples:

```
D:\Codes\winafl>python winafl-cmin.py -h
[...]
Examples of use:
 * Typical use
  winafl-cmin.py -D D:\DRIO\bin32 -t 100000 -i in -o minset -covtype edge -coverage_module m.dll -target_module test.exe -target_method fuzz -nargs 2 -- test.exe @@

 * Dry-run, keep crashes only with 4 workers with a working directory:
  winafl-cmin.py -C --dry-run -w 4 --working-dir D:\dir -D D:\DRIO\bin32 -t 10000 -i in -i C:\fuzz\in -o out_mini -covtype edge -coverage_module m.dll -target_module test.exe -target_method fuzz -nargs 2 -- test.exe @@

 * Read from specific file
  winafl-cmin.py -D D:\DRIO\bin32 -t 100000 -i in -o minset -f foo.ext -covtype edge -coverage_module m.dll -target_module test.exe -target_method fuzz -nargs 2 -- test.exe @@

 * Read from specific file with pattern
  winafl-cmin.py -D D:\DRIO\bin32 -t 100000 -i in -o minset -f prefix-@@-foo.ext -covtype edge -coverage_module m.dll -target_module test.exe -target_method fuzz -nargs 2 -- test.exe @@

 * Typical use with static instrumentation
   winafl-cmin.py -Y -t 100000 -i in -o minset -- test.exe @@
```

<p align="center">
<img alt="winafl-cmin.py" src="screenshots/winafl-cmin.py.png"/>
</p>

## Custom test cases processing

WinAFL supports third party DLLs that can be used to define custom test-cases processing (e.g. to send test cases over network). To enable this option, you need to specify ```-l <path>``` argument.
The DLL should export the following two functions:
```
dll_init()
dll_run(char *data, long size, int fuzz_iterations)
data - content of test case
size - size of test case
fuzz_iterations - defines a current fuzzing iteration number
```

We have implemented two sample DLLs for network-based applications fuzzing that you can customize for your own purposes.

### Network fuzzing

WinAFL's ```custom_net_fuzzer.dll``` allows winAFL to perform network-based applications fuzzing that receive and parse network data. There are several options supported by this DLL that should be provided via the environment variable ```AFL_CUSTOM_DLL_ARGS```:

```
  -a IP address - IP address to send data in
  -U            - use UDP protocol instead of TCP to send data (default TCP)
  -p port       - port to send data in
  -w msec       - delay in milliseconds before actually start fuzzing
```
For example, if your application receives network packets via UDP protocol at port 7714 you should set up the environment variable in the following way: ```set AFL_CUSTOM_DLL_ARGS=-U -p 7714 -a 127.0.0.1 -w 1000 ```

You still need to find target function and make sure that this function receives data from the network, parses it, and returns normally. Also, you can use In App Persistence mode described above if your application runs the target function in a loop by its own.

Additionally, this mode is considered as experimental since we have experienced some problems with stability and performance. However, we found this option very useful and managed to find several vulnerabilities in network-based applications (e.g. in Kollective Kontiki listed above).

There is a second DLL ```custom_winafl_server.dll``` that allows winAFL to act as a server and perform fuzzing of client-based applications. All you need is to set up the port to listen on for incoming connections from your target application. The environment variable ```AFL_CUSTOM_DLL_ARGS=<port_id>``` should be used for this purpose.

#### Note

In case of server fuzzing, if the server socket has the `SO_REUSEADDR` option set like the following code, then this may case `10055` error after some time fuzzing due to the accumulation of `TIME_WAIT` sockets when WinAFL restart the fuzzing process. 
```
setsockopt(s, SOL_SOCKET, SO_REUSEADDR, (char*)&opt, sizeof(int));
```

To avoid this, replace the `SO_REUSEADDR` option by `SO_LINGER` option in the server source code if available.
```
setsockopt(s, SOL_SOCKET, SO_LINGER, (char*)&opt, sizeof(int));
```

## Custom mutators

WinAFL supports loading a custom mutator from a third-party DLL.  You need to implement `dll_mutate_testcase` or `dll_mutate_testcase_with_energy` in your DLL and provide the DLL path to WinAFL via `-l <path>` argument.  WinAFL invokes the custom mutator before all the built-in mutations, and the custom mutator can skip all the built-in mutations by returning a non-zero value.  The `dll_mutate_testcase_with_energy` function is additionally provided an energy value that is equivalent to the number of iterations expected to run in the havoc stage without deterministic mutations. The custom mutator should invoke `common_fuzz_stuff` to run and make WinAFL aware of each new test case.  Below is an example mutator that increments every byte by one: 

```c
u8 dll_mutate_testcase(char **argv, u8 *buf, u32 len, u8 (*common_fuzz_stuff)(char**, u8*, u32))
{
    u8 bailout = 0;
    u8 *newbuf;
    u32 i;
    // duplicate the input buffer
    newbuf = malloc(len);
    if (!newbuf) return bailout;
    memcpy(newbuf, buf, len);
    // increment every byte by one and call common_fuzz_stuff for every new test case
    for (i = 0; i < len; i++) {
       newbuf[i] += 1;
       if (common_fuzz_stuff(argv, newbuf, len)) {
           bailout = 1; // skip the rest of the mutation per common_fuzz_stuff
           break;
       }
    }
    free(newbuf);
    return bailout;
}
```

## FAQ

```
Q: WinAFL reports timeouts while processing initial testcases.
A: You should run your target in debug mode first (-debug flag) and only
   run WinAFL once you get a message in the debug log that everything
   appears to be running normally.

Q: WinAFL runs slower than expected
A: This can commonly happen for several reasons
 - Your target function loads a dll for every iteration. This causes
   DynamoRIO to translate the same code for every iteration which causes
   slowdowns. You will be able to see this in the debug log. To
   resolve, select (or write) your target function differently.
 - Your target function does not close the input file properly, which
   causes WinAFL to kill the process in order to rewrite it. Please refer to
   "How to select a target function" for what a target function should look like.

Q: Can I fuzz DLLs with WinAFL
A: Yes, if you can write a harness that loads a library and runs some
   function within. Write your target function according to "How to select
   a target function" and for best performance, load the dll outside of
   your target function (see the previous question).

Q: Can I fuzz GUI apps with WinAFL
A: Yes, provided that
 - There is a target function that behaves as explained in "How to select
   a target function"
 - The target function is reachable without user interaction
 - The target function runs and returns without user interaction
 If these conditions are not satisfied, you might need to make custom changes
 to WinAFL and/or your target.
```

## Special Thanks

Special thanks to Axel "[0vercl0k](https://twitter.com/0vercl0k)" Souchet of MSRC Vulnerabilities and
Mitigations Team for his contributions!
