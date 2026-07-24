# WinAFL GPU: Zero to Hero Fuzzing Guide

*Contributed by Elias Ibrahim <elie.ibrahim@gmail.com> (Feb 2026)*

Welcome to the definitive guide for harnessing closed-source Windows binaries with **WinAFL GPU**. If you've never fuzzed a program before, this guide is designed exactly for you. 

Traditionally, fuzzing a closed-source Windows program (where you don't have the original source code) was an incredibly painful process. You had to reverse-engineer the binary, manually hunt for internal "parsing" functions, figure out how to call them safely, write C++ wrappings from scratch, and manually compile corpora.

To solve this, we've built a suite of **intelligent Python utilities** that completely automate the hardest parts of the pipeline: finding the target, writing the code, and optimizing the fuzzing loop.

Let's go from zero to crashing a target in 5 phases using the WinAFL Tool Suite.

---

## What is Fuzzing?

**Fuzzing** is simply feeding a computer program mangled, mutated, or randomized data (the "fuzz") and seeing if it crashes. If the program crashes, you've likely found a memory corruption bug (like a buffer overflow) that a hacker could turn into a security exploit. 

To fuzz a program fast (millions of times a minute), we don't open its GUI and click buttons. Instead, we write a **Harness**. A harness is a tiny snippet of code that loads the specific parsing function of the target program (e.g., `LoadImage_Internal()`), passes it mutated bytes, and closes it, looping endlessly. 

Here is how our tools build that harness for you.

---

## Phase 1: Finding a Target (`winafl-target-finder.py`)

You have a folder full of `.dll` and `.exe` files, but you don't know which ones are vulnerable or even capable of being fuzzed. 

**The Tool:** `winafl-target-finder.py scan`
This tool mathematically scores Windows binaries from 0 to 100 on their "fuzzability". It looks for binaries that read files, allocate memory, and manipulate strings (the holy trinity of software bugs).

**The Command:**
```cmd
python winafl-target-finder.py scan "C:\Program Files\VulnerableApp"
```

**What happens?**
The tool will scan the directory and print a ranked leaderboard. It might tell you that `image_decoder.dll` scored a 95/100 because it exports a function named `parse_file` and calls `fread()` and `VirtualAlloc()`. You have your target!

---

## Phase 2: Generating the Harness (`winafl-harness-builder.py`)

Now that you know `image_decoder.dll` is your target, you need a C++ wrapper to loop its parsing function. 

**The Tool:** `winafl-harness-builder.py` 
This tool acts as a robotic reverse-engineer. It disassembles the target, counts its arguments, figures out if it wants a file path or a memory buffer, checks for safety (does it call `ExitProcess`?), and generates the perfect C harness file automatically.

**The Command:**
Use the pipeline to feed the finder directly into the builder:
```cmd
python winafl-target-finder.py analyze image_decoder.dll --offset 0x1A40 | python winafl-harness-builder.py --pipe > harness.c
```
*(You can get the offset of interesting functions from the Phase 1 target finder's deep analysis).*

**What happens?**
You will instantly get a `harness.c` file written for you. It automatically contains the code to `LoadLibrary` your DLL, resolve the function, and safely execute it in a `__try/__except` block.

**Compile it:**
Open a Visual Studio developer command prompt:
```cmd
cl.exe /nologo /W3 /O2 harness.c /link /OUT:harness.exe
```

---

## Phase 3: Building a Quality Seed Corpus (`seeds` & `winafl-cmin.py`)

A fuzzer needs examples of *valid* files to start with. If it's fuzzing an image decoder, it needs valid images to mutate. A folder of these starting files is called the **Corpus**.

**The Tool:** `winafl-target-finder.py seeds`
This command automatically rummages through your Windows system looking for tiny, valid files of the format you request.

**The Command:**
```cmd
python winafl-target-finder.py seeds png .\corpus_in
```

### Minimizing the Corpus
If you feed the fuzzer 50 images that are essentially identical (e.g., just different colors), the fuzzer wastes time. We want a small corpus where *every file triggers different code logic*. 

**The Tool:** `winafl-cmin.py` (Corpus Minimizer)
This runs every seed through the target using DynamoRIO to map its execution path. If two seeds hit the exact same lines of code, one is deleted.

**The Command:**
```cmd
python winafl-cmin.py -D C:\DynamoRIO\bin32 -t 10000 -i .\corpus_in -o .\corpus_minimized -target_module harness.exe -target_method fuzz_target -nargs 2 -- harness.exe @@
```
Now you have a hyper-optimized, deduplicated starting point in `.\corpus_minimized`.

---

## Phase 4: Launching the Campaign

It's time to unleash WinAFL. 

Usually, the WinAFL command line is horribly complex to type by hand. Let's ask our tool to generate the exact command string for us!

**The Tool:** `winafl-target-finder.py generate`

**The Command:**
```cmd
python winafl-target-finder.py generate image_decoder.dll 0x1A40 -i .\corpus_minimized -o .\fuzz_out -D C:\DynamoRIO\bin32
```

Copy the command it spits out and run it! The WinAFL dashboard will appear, and your executions-per-second counter will start flying as it mutates files and executes `harness.exe`.

---

## Phase 5: Monitoring Success (`whatsup` & `plot`)

If you leave your fuzzer running overnight, you want to know exactly what it achieved without deciphering raw logs.

**The Tool:** `winafl-whatsup.py`
This prints a clean summary of your fuzzing campaign, including total runtime, average speeds, and how many unique crashes it discovered.

**The Command:**
```cmd
python winafl-whatsup.py .\fuzz_out
```

**The Tool:** `winafl-plot.py`
If you want to show off your progress in a report, this tool generates beautiful HTML/Gnuplot graphs showing coverage growth, execution speeds, and crash frequency over time.

**The Command:**
```cmd
python winafl-plot.py .\fuzz_out .\graphs_dir
```

---

## Summary of the Automatic Workflow
1. **Find Target**: `winafl-target-finder.py scan`
2. **Build Harness**: `... target-finder.py analyze ... | winafl-harness-builder.py` -> `cl.exe harness.c`
3. **Gather Seeds**: `winafl-target-finder.py seeds png in_dir`
4. **Minimize**: `winafl-cmin.py -i in_dir -o min_dir ...`
5. **Fuzz**: Execute the generated `afl-fuzz.exe` command!
6. **Profit**: Check `winafl-whatsup.py` for crashes and `winafl-plot.py` for charts.
