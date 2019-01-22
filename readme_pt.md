# WinAFL Intel PT mode

WinAFL has an Intel PT mode which, at this time, is very basic and very experimental

## How it works

Intel PT (Processor Tracing) is a feature on modern Intel CPUs that allows tracing code executed by the CPU. If the trace collection is enabled, the CPU generates a highly compressed trace of the instructions executed. This trace can be retrieved and decoded in software later.

Windows from Windows 10 v1809 include an Intel PT driver. Although this is, at this time, undocumented and there is no official API, Alex Ionescu wrote the [WinIPT library](https://github.com/ionescu007/winipt) for interacting with the driver. This is what WinAFL uses for trace collection.

When a target is fuzzed with WinAFL in Intel PT mode, WinAFL opens a target in a debugger. The debugger implenents the WinAFL persistence (looping over target function without the need to restart the process for every iteration), monitors for crashes, loaded modules etc. Before every iteration, the debugger enables Intel PT tracing for the target process, the trace is stored during the execution, and, after the iteration finishes, the collected trace is analyzed and AFL coverage map is updated.

## Building and using

To build WinAFL with Intel PT support add -DINTELPT=1 to the build options.

To use the Intel PT mode set the -P flag (without any arguments) instead of -D flag (for DynamoRIO) when calling afl-fuzz.exe. Intel PT tracing mode understands the same instrumentation flags as the DynamoRIO mode.

## Caveats

Intel PT support is pretty basic at this time and there is a number of known weaknesses:

 - A relatively recent Intel CPU with the Processor Tracing feature is needed for this mode and Windows 10 v1809 is needed to be able to interact with it. Running WinAFL inside a VM won't work unless the VM software explicitly supports Intel PT.

 - Currently, WinAFL only partially decodes the trace, which results in a very coarse coverage information. Currently, only TIP packets are decoded, which capture information about the indirect jumps and calls and (sometimes) returns but don't capture information about e.g. conditional jumps. This is similar to how Intel PT is used in [Honggfuzz](https://github.com/google/honggfuzz)

 - Intel PT trace is written in a ring buffer by the CPU and WinAFL needs to read out this trace. If the trace is generated quicker than WinAFL can read it out, the ring buffer will wrap around and this will result in a corrupted trace. WinAFL attempts to resolve this by using a pretty large ring buffer size (see the TRACE_BUFFER_SIZE_STR flag), but there are still no guarantees if, e.g. the thread reading out the trace becomes unexpectedly slow for some reason.

 - Similarly, WinAFL can collect only limited amount of trace from the execution (see the MAX_TRACE_SIZE flag). This should be sufficient for most targets, but may not be sufficient if a single iteration runs for a long time. In this case, the trace will be truncated and everything past MAX_TRACE_SIZE will be ignored.

 - Currently, WinAFL ignores the -coverage_module instrumentation flags and collects coverage from all modules. In combination with decoding only some trace packets, this is not necessarily a bad thing. However, it does result in some junk coverage and detecting new coverage in cases where this would not normally be desirable.

 - Currently, WinAFL will only record the trace from a thread that executes the target function. Currently, Intel PT driver does collect information from all threads and the debugger gets information about threads being created and threads exiting. However, when the debugger gets the EXIT_THREAD_DEBUG_EVENT, it is too late and the trace information for this thread is already lost. WinAFL could read out the trace while the thread is still running, however there would be a gap between the last time the trace was read out and the time the thread exited. This would result in a non-deterministic trace with a part of it cut off and, likely, not recording trace for very short threads. Thus, to address this problem deterministically, a better way of tracking thread exits is needed.

 - There is a known issue where obtaining target method offset from name using symbols doesn't work for 32-bit targets. The reason for this is currently unknown. Exported names should still work though.

## Examples

Example command line:

```
afl-fuzz.exe -i testin -o testout -P -t 20000 -- -coverage_module test.exe -fuzz_iterations 2000 -target_module test.exe -target_method main -nargs 2 -- test.exe @@
```
