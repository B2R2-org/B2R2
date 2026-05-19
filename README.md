![alt text](https://b2r2.org//images/b2r2-2d-white.png)

![B2R2](https://github.com/B2R2-org/B2R2/actions/workflows/debug.yml/badge.svg)
![B2R2](https://github.com/B2R2-org/B2R2/actions/workflows/release.yml/badge.svg)
![](https://img.shields.io/github/license/B2R2-org/B2R2.svg?style=flat)
[![](https://img.shields.io/nuget/v/B2R2.RearEnd.Launcher)](https://www.nuget.org/packages/B2R2.RearEnd.Launcher/)

B2R2
====

B2R2 is a fully managed binary analysis framework written in F#. It provides a
rich set of algorithms, functions, and tools for reverse engineering, program
analysis, and binary-level inspection.

The name B2R2 takes inspiration from [R2-D2](https://en.wikipedia.org/wiki/R2-D2),
the iconic robot from Star Wars. Originally named *B2-R2*, the project later
adopted the dash-free form *B2R2* because .NET identifiers and namespaces do not
allow hyphens. The name reflects the project's purpose: "B" and "2" suggest
binary and two-state computation, while "R" stands for reversing. In short,
B2R2 is built for binary reversing.

B2R2?
-----

1. B2R2 is *analysis-friendly*: it is written in F#, a language well suited for
   building program analyzers thanks to features such as pattern matching,
   algebraic data types, and expressive functional abstractions.

1. B2R2 is *fast*: its core binary analysis engine is designed for efficiency and
   written in a
   [functional-first](https://en.wikipedia.org/wiki/F_Sharp_(programming_language))
   style. This makes it a natural fit for *pure parallelism* across common
   analysis tasks such as instruction lifting and CFG recovery.

1. B2R2 is *easy* to use: as a fully managed library, it avoids complicated
   native dependency setup. Install the
   [.NET SDK](https://dotnet.microsoft.com/download), and you are ready to go.
   Native
   [IntelliSense](https://docs.microsoft.com/en-us/visualstudio/ide/using-intellisense)
   support also makes the APIs easier to explore.

1. B2R2 is *OS-independent*: it works on Linux, macOS, and Windows, as well as
   any other platform supported by .NET.

1. B2R2 is *interoperable*: it is not tied to a single programming language.
   In principle, B2R2 APIs can be used from any
   [CLI-supported language](https://en.wikipedia.org/wiki/List_of_CLI_languages).

Features?
---------

B2R2 supports instruction parsing, binary disassembly, assembly, control-flow
recovery, and other core building blocks for binary analysis. It also includes
several user-facing command-line tools comparable to readelf and objdump, while
remaining platform-agnostic. B2R2 currently supports four binary file formats:
ELF, PE, Mach-O, and WebAssembly.

The table below summarizes the features currently supported by B2R2. Some areas
are still in progress, and contributions are welcome. Before opening a pull
request, please make sure to read our [contribution guideline](CONTRIBUTING.md).

<table>
  <tr>
    <th width="178px">CPU</th>
    <th width="96px" class="text-center">Docs</th>
    <th width="96px" class="text-center">Ins Parsing</th>
    <th width="96px" class="text-center">Disasm</th>
    <th width="96px" class="text-center">Lifting</th>
    <th width="96px" class="text-center">CFG Recovery</th>
    <th width="96px" class="text-center">Assembly</th>
  </tr>
  <tr>
    <td><b>x86</b></td>
    <td align="center">:full_moon:</td>
    <td align="center">:full_moon:</td>
    <td align="center">:full_moon:</td>
    <td align="center">:full_moon:</td>
    <td align="center">:full_moon:</td>
    <td align="center">:full_moon:</td>
  </tr>
  <tr>
    <td><b>x86-64</b></td>
    <td align="center">:full_moon:</td>
    <td align="center">:full_moon:</td>
    <td align="center">:full_moon:</td>
    <td align="center">:full_moon:</td>
    <td align="center">:full_moon:</td>
    <td align="center">:full_moon:</td>
  </tr>
  <tr>
    <td><b>ARMv7</b></td>
    <td align="center">:full_moon:</td>
    <td align="center">:full_moon:</td>
    <td align="center">:full_moon:</td>
    <td align="center">:full_moon:</td>
    <td align="center">:first_quarter_moon:</td>
    <td align="center">:new_moon:</td>
  </tr>
  <tr>
    <td><b>ARMv8 (AArch64)</b></td>
    <td align="center">:full_moon:</td>
    <td align="center">:full_moon:</td>
    <td align="center">:full_moon:</td>
    <td align="center">:full_moon:</td>
    <td align="center">:first_quarter_moon:</td>
    <td align="center">:new_moon:</td>
  </tr>
  <tr>
    <td><b>MIPS32</b></td>
    <td align="center">:full_moon:</td>
    <td align="center">:full_moon:</td>
    <td align="center">:full_moon:</td>
    <td align="center">:full_moon:</td>
    <td align="center">:first_quarter_moon:</td>
    <td align="center">:new_moon:</td>
  </tr>
  <tr>
    <td><b>MIPS64</b></td>
    <td align="center">:full_moon:</td>
    <td align="center">:full_moon:</td>
    <td align="center">:full_moon:</td>
    <td align="center">:full_moon:</td>
    <td align="center">:first_quarter_moon:</td>
    <td align="center">:new_moon:</td>
  </tr>
  <tr>
    <td><b>EVM</b></td>
    <td align="center">:full_moon:</td>
    <td align="center">:full_moon:</td>
    <td align="center">:full_moon:</td>
    <td align="center">:full_moon:</td>
    <td align="center">:full_moon:</td>
    <td align="center">:new_moon:</td>
  </tr>
  <tr>
    <td><b>TMS320C6000</b></td>
    <td align="center">:full_moon:</td>
    <td align="center">:full_moon:</td>
    <td align="center">:full_moon:</td>
    <td align="center">:new_moon:</td>
    <td align="center">:first_quarter_moon:</td>
    <td align="center">:new_moon:</td>
  </tr>
  <tr>
    <td><b>AVR</b></td>
    <td align="center">:full_moon:</td>
    <td align="center">:full_moon:</td>
    <td align="center">:full_moon:</td>
    <td align="center">:full_moon:</td>
    <td align="center">:first_quarter_moon:</td>
    <td align="center">:new_moon:</td>
  </tr>
  <tr>
    <td><b>PA-RISC</b></td>
    <td align="center">:full_moon:</td>
    <td align="center">:full_moon:</td>
    <td align="center">:full_moon:</td>
    <td align="center">:new_moon:</td>
    <td align="center">:first_quarter_moon:</td>
    <td align="center">:new_moon:</td>
  </tr>
  <tr>
    <td><b>PPC32</b></td>
    <td align="center">:full_moon:</td>
    <td align="center">:full_moon:</td>
    <td align="center">:full_moon:</td>
    <td align="center">:full_moon:</td>
    <td align="center">:first_quarter_moon:</td>
    <td align="center">:new_moon:</td>
  </tr>
  <tr>
    <td><b>SPARC</b></td>
    <td align="center">:full_moon:</td>
    <td align="center">:full_moon:</td>
    <td align="center">:full_moon:</td>
    <td align="center">:full_moon:</td>
    <td align="center">:first_quarter_moon:</td>
    <td align="center">:new_moon:</td>
  </tr>
  <tr>
    <td><b>SH4</b></td>
    <td align="center">:full_moon:</td>
    <td align="center">:full_moon:</td>
    <td align="center">:full_moon:</td>
    <td align="center">:new_moon:</td>
    <td align="center">:first_quarter_moon:</td>
    <td align="center">:new_moon:</td>
  </tr>
  <tr>
    <td><b>RISC-V</b></td>
    <td align="center">:full_moon:</td>
    <td align="center">:full_moon:</td>
    <td align="center">:full_moon:</td>
    <td align="center">:full_moon:</td>
    <td align="center">:first_quarter_moon:</td>
    <td align="center">:new_moon:</td>
  </tr>
  <tr>
    <td><b>S390</b></td>
    <td align="center">:full_moon:</td>
    <td align="center">:full_moon:</td>
    <td align="center">:full_moon:</td>
    <td align="center">:new_moon:</td>
    <td align="center">:first_quarter_moon:</td>
    <td align="center">:new_moon:</td>
  </tr>
</table>

Dependencies?
-------------

B2R2 keeps its dependency footprint intentionally small to make builds simple
and to keep the core focused on efficient algorithms and data structures for
binary analysis. The core library has no external dependencies, and most
external libraries are optional and used only by specific components or tools.
Below is the list of external libraries used by the project.

- [System.IO.Hashing](https://www.nuget.org/packages/System.IO.Hashing)
- [FSharp.Compiler.Service](https://www.nuget.org/packages/FSharp.Compiler.Service)
- [FParsec](https://www.nuget.org/packages/FParsec)
- [BenchmarkDotNet](https://www.nuget.org/packages/BenchmarkDotNet)
- [Avalonia.FuncUI](https://www.nuget.org/packages/Avalonia.FuncUI)

API Documentation
-----------------

Our documentation is generated with
[fsdocs](https://github.com/fsprojects/FSharp.Formatting/) and available at
https://b2r2.org/B2R2/.

Example
-------

Let's try using the B2R2 APIs.

1. First, create an empty directory named `DIRNAME`:

    ```
    mkdir DIRNAME
    cd DIRNAME
    ```

1. Then, create an empty console project with the `dotnet` command-line tool:

    ```
    $ dotnet new console -lang F#
    ```

1. Add the NuGet package *B2R2.FrontEnd.API* to the project:

    ```
    $ dotnet add package B2R2.FrontEnd.API
    ```

1. Modify the `Program.fs` file with your favorite editor as follows:

    ```fsharp
    open B2R2
    open B2R2.FrontEnd

    [<EntryPoint>]
    let main argv =
      let isa = ISA "amd64"
      let bytes = [| 0x65uy; 0xffuy; 0x15uy; 0x10uy; 0x00uy; 0x00uy; 0x00uy |]
      let hdl = BinHandle(bytes, isa)
      let lifter = hdl.NewLiftingUnit()
      let ins = lifter.ParseInstruction 0UL // parse the instruction at offset 0
      lifter.LiftInstruction ins |> printfn "%A"
      0
    ```

1. Run it by typing `dotnet run`. You should see lifted IR statements in your
   console. That's it! You just lifted an Intel instruction with only a few
   lines of F# code.

Build
-----

Building B2R2 is straightforward. Install the .NET 10 SDK or later, and you are
ready to build from the source root.

- To build B2R2 in release mode, run `dotnet build -c Release`.

- To build B2R2 in debug mode, run `dotnet build`.

For more information about setting up an F# development environment, visit the
official F# website: http://fsharp.org/.

Credits
-------

B2R2 was developed by members of the
[SoftSec Lab](https://softsec.kaist.ac.kr/) at KAIST in collaboration with the
[Cyber Security Research Center](http://csrc.kaist.ac.kr/) (CSRC) at KAIST. See
[AUTHORS.md](AUTHORS.md) for the full list of contributors.

Citation
--------

If you use B2R2 in your research, please consider citing our
[paper](https://softsec.kaist.ac.kr/~sangkilc/papers/jung-bar19.pdf):

```bibtex
@INPROCEEDINGS{jung:bar:2019,
  author = {Minkyu Jung and Soomin Kim and HyungSeok Han and Jaeseung Choi and Sang Kil Cha},
  title = {{B2R2}: Building an Efficient Front-End for Binary Analysis},
  booktitle = {Proceedings of the NDSS Workshop on Binary Analysis Research},
  year = 2019
}
```

Publications
------------

Below are papers that use or build on B2R2. If your work should be included,
please open a pull request.

- EVMpress: Precise Type Inference for Next-Generation EVM Decompilation, CBT 2025 [(PDF)](https://softsec.kaist.ac.kr/~sangkilc/papers/kim-cbt25.pdf)
- Towards Sound Reassembly of Modern x86-64 Binaries, ASPLOS 2025 [(PDF)](https://softsec.kaist.ac.kr/~sangkilc/papers/kim-asplos25.pdf)
- PoE: A Domain-Specific Language for Exploitation, SVCC 2024 [(PDF)](https://softsec.kaist.ac.kr/~sangkilc/papers/kim-svcc24.pdf)
- FunProbe: Probing Functions from Binary Code through Probabilistic Analysis, FSE 2023 [(PDF)](https://softsec.kaist.ac.kr/~sangkilc/papers/kim-fse23.pdf)
- How'd Security Benefit Reverse Engineers? The Implication of Intel CET on Function Identification, DSN 2022 [(PDF)](https://softsec.kaist.ac.kr/~sangkilc/papers/kim-dsn2022.pdf)
- Smartian: Enhancing Smart Contract Fuzzing with Static and Dynamic Data-Flow Analyses, ASE 2021 [(PDF)](https://softsec.kaist.ac.kr/~jschoi/data/ase2021.pdf)
- NTFuzz: Enabling Type-Aware Kernel Fuzzing on Windows with Static Binary Analysis, Oakland 2021 [(PDF)](https://softsec.kaist.ac.kr/~jschoi/data/oakland2021.pdf)
