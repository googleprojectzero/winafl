# WinAFL Intel PT mode

## How it works

Intel PT (Processor Tracing) is a feature on modern Intel CPUs that allows tracing code executed by the CPU. If the trace collection is enabled, the CPU generates a highly compressed trace of the instructions executed. This trace can be retrieved and decoded in software later.

Windows from Windows 10 v1809 include an Intel PT driver. Although this is, at this time, undocumented and there is no official API, Alex Ionescu wrote the [WinIPT library](https://github.com/ionescu007/winipt) for interacting with it. This is what WinAFL uses for trace collection.

When a target is fuzzed with WinAFL in Intel PT mode, WinAFL opens the target in a debugger. The debugger implenents the WinAFL persistence (looping over target function without the need to restart the process for every iteration), monitors for crashes, loaded modules etc. Before every iteration, the debugger enables Intel PT tracing for the target process and, after the iteration finishes, the trace is retrived and analyzed, updating the AFL coverage map.

## Building and using

To build WinAFL with Intel PT support `-DINTELPT=1` must be added to the build options.

To use the Intel PT mode set the -P flag (without any arguments) instead of -D flag (for DynamoRIO) when calling afl-fuzz.exe. Intel PT tracing mode understands the same instrumentation flags as the DynamoRIO mode, as well as several others:

 - `-trace_size <size>` The size (in bytes) of trace information to collect for every iteration. See remarks below. The size *must* be a factor of two larger than 4096.
 
 - `-decoder <decoder>` The decoder to use to process the trace. Supported options are `tip`, `tip_ref` and `full` (default). See remarks on each below.
 
 - `-nopersistent_trace` By default, due to large performance hit associated, WinAFL will not restart tracing for each iteration. If this optimization ever causes problems, it can be turned off via this flag. Mostly here for debugging reasons.

 - `-trace_cache_size <size>` The size (in bytes) of trace cache. Used only in combination with the `full` decorer.

The following trace decoders are available:
 
 - `full_ref` Uses Intel's reference implementation to fully decode the trace. Note that full trace decoding introduces a significant overhead. Full trace decoding requires information about the code being executed. WinAFL accomplishes this by saving the memory from all executable modules in the process once they are loaded. However, if the instruction pointer ever ends up outside of an executable module (e.g. due to target using some kind of JIT), the decoding is going to fail and the trace will be decoded only partially. Additinally, if the target modifies executable modules on the fly, the result of the decoding is going to be unpredictable.

 - `full` (default) A custom decoder that adds a trace caching layer on top of Intel's reference decoder. Like the `full_ref` decoder it fully decodes all basic blocks in the trace (also provided that code is't generated / modified dynamically), but is significantly faster.
   
 - `tip_ref` Uses Intel's reference decoder implementation and decodes only the packets that contain the raw IP address (emitted for e.g. indirect jumps and calls, sometimes returns) but don't decode other packets, e.g. containing info about indirect jumps. This option does not require having any information on the code being executed and is much faster than full decoding. This is similar to how Intel PT is used in [Honggfuzz](https://github.com/google/honggfuzz).
   
 - `tip` A faster custom implementation of the `tip_ref` decoder. It should behave the same as `tip_ref`

## Limitations and other remarks

 - A relatively recent Intel CPU with the Processor Tracing feature is needed for this mode and Windows 10 v1809 is needed to be able to interact with it. Running WinAFL inside a VM won't work unless the VM software explicitly supports Intel PT.

 - The CPU writes trace information into a ring buffer. If the space in the ring buffer is not sufficient to store the full trace of the iteration execution, the buffer will wrap around and only the last `trace_size` bytes (or a little less, depending on the synchronization packets) will be available for processing. You should set the `trace_size` flags to be able to contain the full trace for a sample that exhibits full target behavior. The default `trace_size` should be sufficient for most targets, however reducing it might increase performance for small targets and you might want to increase it if you get trace buffer overflow warnings.
 
 - Currently, WinAFL will only record the trace from a thread that executes the target function. In most cases this is desirable, but not always. Currently, Intel PT driver does collect information from all threads and the debugger gets information about threads being created and threads exiting. However, when the debugger gets the EXIT_THREAD_DEBUG_EVENT, it is too late and the trace information for this thread is already lost. WinAFL could read out the trace while the thread is still running, however there would be a gap between the last time the trace was read out and the time the thread exited. This would result in a non-deterministic trace with a part of it cut off and, likely, not recording trace for very short threads. Thus, to address this problem deterministically, a better way of tracking thread exits is needed.

## Examples

Example command line:

```
afl-fuzz.exe -i testin -o testout -P -t 20000 -- -coverage_module test.exe -fuzz_iterations 2000 -target_module test.exe -target_method main -nargs 2 -- test.exe @@
```
