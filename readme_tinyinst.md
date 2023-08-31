# TinyInst instrumentation

TinyInst is a lightweight dynamic instrumentation library that can be used to instrument only selected module(s) in the process, while leaving the rest of the process to run natively. WinAFL includes a custom TinyInst client that can collect both basic block and edge coverage into an AFL coverage map.

## Building and using

To build WinAFL with TinyInst support, `-DTINYINST=1` must be added to the build options. For the full building instructions, see the main readme.

Similar to other modes, the usage is

```
afl-fuzz -y [afl options] -- [instrumentation options] -- target_cmd_line
```

where the `-y` flag is used to select TinyInst mode.

The full list of instrumentation options can be found in the [TinyInst readme](https://github.com/googleprojectzero/TinyInst). Note that, while these options are mostly similar to instrumentation options in DynamoRIO mode:
  - Some flags have differen names, e.g. `-instrument_module` (TinyInst) vs. `-coverage_module` (DynamoRIO).
  - Some additional flags are needed to take advantage of persistence mode, specifically `-persist` and `-loop` flags.

Instead of listing all of the options from TinyInst readme, let's examine a basic usage example

```
afl-fuzz.exe -y -i in -o out -t 20000 -- -instrument_module gdiplus.dll -instrument_module WindowsCodecs.dll -target_module test_gdiplus.exe -target_method main -nargs 2 -iterations 5000 -persist -loop -- C:\work\winafl\build64\bin\RelWithDebInfo\test_gdiplus.exe @@
```

which fuzzes the `test_gdiplus` harness included with WinAFL. As stated previously, `-y` is used to select the TinyInst mode. `-i in -o out -t 20000` are standard afl flags used to set input and output directories as well as the timeout, respectively.

`-instrument_module` specifies which module to instrument. This is similar to `-coverage_module` flag in DynamoRIO mode. There can be multiple `-instrument_module` flags for different modules. In our example, we'll be instrumenting (collecting coverage from) two modules, `gdiplus.dll` and `WindowsCodecs.dll`

`-target_module` and `-target_method` specify which function to run in WinAFL's persistent mode. `-target_module` identifies the module where the function is located (`test_gdiplus.exe` in the example), while `-target_method` specifies the name of the function (main in this case). In case where the symbols (function names) aren't available for the target module, `-target_offset` can be used instead, which specifies the offset in memory from start of the module to the target function (for example `-target_offset 0x16a0`).

`nargs` specifies how many arguments the target function takes in order to be able to restore the arguments for every run.

`-persist` instructs TinyInst to use the persistent mode and keep the target process alive when the target function returns.

`-loop` instructs TinyInst to jump to the start of target function after it returns. `-persist` and `-loop` together enable the "classic" WinAFL persistent mode. However there might be cases where one of these flags is desirable without the other, for example in case where the target process calls the target function repeatedly on its own, `-persist` flag can be used without `-loop`

`-iterations` specifies how many times to run the target function in persistent mode without restarting the target process.

To debug issues, it might be useful to run the target under TinyInst but without the fuzzer. This can be done using `litecov.exe` tool that comes with TinyInst. For example, running `litecov.exe` with the same instrumentation optios as above (except the number of iteration reduced)

```
litecov.exe -instrument_module gdiplus.dll -instrument_module WindowsCodecs.dll -target_module test_gdiplus.exe -target_method main -nargs 2 -iterations 10 -persist -loop -- C:\work\winafl\build64\bin\RelWithDebInfo\test_gdiplus.exe in\in.txt
```

might produce the following output

```
Instrumented module gdiplus.dll, code size: 1409024
Target function returned normally
Found 1094 new offsets in gdiplus.dll
Target function returned normally
Found 1 new offsets in gdiplus.dll
Target function returned normally
Target function returned normally
Target function returned normally
Target function returned normally
Target function returned normally
Target function returned normally
Target function returned normally
Target function returned normally
```

This lets us know that
 - There was code executing in the gdiplus.dll module and TinyInst collected some coverage from it.
 - The target function ran 10 times (as expected) and returned normally every time (i.e. no crashes or hangs)

So it gives us a good indication that the instrumentation options are set correctly and the target is running correctly under TinyInst.

There are additional flags that can be useful for debugging such as `-trace_debug_events` which, among other things, lists modules loaded by the target process. Note that `-trace_debug_events` might report exceptions in the target process, but these don't necessarily mean crashes or errors (as long as you don't see a message about the process crashing) as TinyInst uses exceptions under the hood.

