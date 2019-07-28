# Dynamorio Instrumentation mode

## How it works

This mode relies on dynamic instrumentation using DynamoRIO
(http://dynamorio.org/) to measure and extract target coverage. This approach
has been found to introduce an overhead about 2x compared to the native
execution speed, which is comparable to the original AFL in binary
instrumentation mode.

In order to use it you need to

 - download and build DynamoRIO sources or download DynamoRIO Windows binary
package from https://github.com/DynamoRIO/dynamorio/wiki/Downloads

 - Specify the `-DDynamoRIO_DIR` option when building WinAFL

## Supported instrumentation flags

The following instrumentation options are supported in the DynamoRIO mode:

```
  -covtype         - the type of coverage being recorded. Supported options are
                     bb (basic block, default) or edge.

  -coverage_module - module for which to record coverage. Multiple module flags
                     are supported.

  -target_module   - module which contains the target function to be fuzzed.
                     Either -target_method or -target_offset need to be
                     specified together with this option.

  -target_method   - name of the method to fuzz in persistent mode. For this to
                     work either the method needs to be exported or the symbols
                     for target_module need to be available. Otherwise use
                     -target_offset instead.

  -target_offset   - offset of the method to fuzz from the start of the module.

  -fuzz_iterations - Maximum number of iterations for the target function to run
                     before restarting the target process.

  -nargs           - Number of arguments the fuzzed method takes. This is used
                     to save/restore the arguments between runs.

  -call_convention - The default calling convention is cdecl on 32-bit x86
                     platforms and Microsoft x64 for Visual Studio 64-bit
                     applications. Possible values:
                         * fastcall: fastcall
                         * ms64: Microsoft x64 (Visual Studio)
                         * stdcall: cdecl or stdcall
                         * thiscall: thiscall

  -debug           - Debug mode. Does not try to connect to the server. Outputs
                     a log file containing loaded modules, opened files and
                     coverage information.

  -logdir          - specifies in which directory the log file will be written
                     (only to be used with -debug).

  -thread_coverage - If set, WinAFL will only collect coverage from a thread
                     that executed the target function
```

## Using

Note: If you are using pre-built binaries you'll need to download DynamoRIO
release 7.1.0-1 from https://github.com/DynamoRIO/dynamorio/wiki/Downloads.
If you built WinAFL from source, you can use whatever version of DynamoRIO
you used to build WinAFL.

In general, you should perform the following steps when fuzzing a new target:

1. Make sure your target is running correctly without instrumentations.

2. Open the target binary in WinDbg and locate the function you want to fuzz.
Note the offset of the function from the start of the module. For example, if
you want to fuzz the main function and happen to have symbols around, you can
use the following windbg command:

```
x test!main
```

3. Make sure that the target is running correctly under DynamoRIO. For this
purpose you can use the standalone debug mode of WinAFL client which does not
require connecting to afl-fuzz. Make sure you use the drrun.exe and winafl.dll
version which corresponds to your target (32 vs. 64 bit).

Example command line:

```
path\to\DynamoRIO\bin64\drrun.exe -c winafl.dll -debug
-target_module test_gdiplus.exe -target_offset 0x16e0 -fuzz_iterations 10
-nargs 2 -- test_gdiplus.exe input.bmp
```

You should see the output corresponding to your target function being run 10
times after which the target executable will exit. A .log file should be
created in the current directory. The log file contains useful information
such as the files and modules loaded by the target as well as the dump of AFL
coverage map. In the log you should see pre_fuzz_handler and post_fuzz_handler
being run exactly 10 times as well as your input file being open in each
iteration. Note the list of loaded modules for setting the -coverage_module
flag. Note that you must use the same values for module names as seen in the
log file (not case sensitive).

4. Now you should be ready to fuzz the target. First, make sure that both
afl-fuzz.exe and winafl.dll are in the current directory. As stated earlier,
the command line for afl-fuzz on Windows is:

```
afl-fuzz [afl options] -- [instrumentation options] -- target_cmd_line
```

Please refer above for the list of supported AFL and instrumentation options.

In AFL options, you must specify the DynamoRIO binaries directory via the new
-D option. You need to match the DynamoRIO and winafl.dll build (32 vs. 64 bit)
to the target binary. -t (timeout) option is mandatory for WinAFL as execution
time can vary significantly under instrumentation so it's not a good idea to
rely on the auto-determined values.

You can use the same WinAFL options as in step 2 but remember to exclude the
-debug flag and you'll probably want to increase the iteration count.

As in afl-fuzz on Linux you can replace the input file parameter of the target
binary with @@.

An example command line would look like:

```
afl-fuzz.exe -i in -o out -D C:\work\winafl\DynamoRIO\bin64 -t 20000 --
-coverage_module gdiplus.dll -coverage_module WindowsCodecs.dll
-fuzz_iterations 5000 -target_module test_gdiplus.exe -target_offset 0x16e0
-nargs 2 -- test_gdiplus.exe @@
```

Alternately, if symbols for test_gdiplus.exe are available, you can use
-target_method instead of -target_offset like so:

```
afl-fuzz.exe -i in -o out -D C:\work\winafl\DynamoRIO\bin64 -t 20000 --
-coverage_module gdiplus.dll -coverage_module WindowsCodecs.dll
-fuzz_iterations 5000 -target_module test_gdiplus.exe -target_method main
-nargs 2 -- test_gdiplus.exe @@
```

That's it. Happy fuzzing!


## In App Persistence mode

This feature is a tweak for the traditional "target function" approach and aims
to loosen the requirements of the target function to do both reading
an input file and processing the input file.

In some applications it's quite challenging to find a target function
that with a simple execution redirection won't break global states and will do
both reading and processing of inputs.

This mode assumes that the target application will actually loop
the target function by itself, and will handle properly its global state
For example a udp server handling packets or a js interpreter running inside
a while loop.

This mode works as following:
1. Your target runs until hitting the target function.
2. The afl server starts instrumenting the target.
3. Your target runs until hitting the target function again.
4. The afl server stops instrumenting current cycle and starts a new one.

Usage:

Add the following option to the winafl arguments:
`-persistence_mode in_app`

`-nargs` isn't necessary in this mode.

Example usage on the supplied test.exe:

```
afl-fuzz.exe -i in -o out -D <dynamorio bin path> -t 100+ -- -coverage_module test.exe -fuzz_iterations 5000 -target_module test.exe -target_offset 0x1000 -persistence_mode in_app -- test.exe @@ loop
```


