![alt text](https://b2r2.org//images/b2r2-2d-white.png)

![B2R2](https://github.com/B2R2-org/B2R2/actions/workflows/debug.yml/badge.svg)
![B2R2](https://github.com/B2R2-org/B2R2/actions/workflows/release.yml/badge.svg)
![](https://img.shields.io/github/license/B2R2-org/B2R2.svg?style=flat)
[![](https://img.shields.io/nuget/v/B2R2.RearEnd.Launcher)](https://www.nuget.org/packages/B2R2.RearEnd.Launcher/)

B2R2
====

B2R2 is a collection of useful algorithms, functions, and tools for **binary
analysis**, written purely in F# (in .NET lingo, it is purely managed code).
B2R2 has been named after [R2-D2](https://en.wikipedia.org/wiki/R2-D2), a famous
fictional robot appeared in the Star Wars. In fact, B2R2's original name was
*B2-R2*, but we decided to use the name *B2R2* instead, because .NET does not
allow dash (-) characters in identifiers (or namespaces). The name essentially
represents "binary" or "two": "binary" itself means "two" states anyways. "B"
and "2" mean "binary", and "R" indicates *reversing*.

B2R2?
-----

1. B2R2 is *analysis-friendly*: it is written in F#, which provides all the
   syntactic goodies for writing program analyzers, such as pattern matching,
   algebraic data types, and etc.

1. B2R2 is *fast*: it has a fast and efficient front-end engine for binary
   analysis, which is written in a
   [functional-first](https://en.wikipedia.org/wiki/F_Sharp_(programming_language))
   way. Therefore, it naturally supports *pure parallelism* for various binary
   analysis tasks, such as instruction lifting, CFG recovery, and etc.

1. B2R2 is *easy* to play with: there is absolutely no dependency hell for B2R2
   because it is a fully-managed library.  All you need to do is to install
   [.NET SDK](https://dotnet.microsoft.com/download), and you are ready to
   go! Native
   [IntelliSense](https://docs.microsoft.com/en-us/visualstudio/ide/using-intellisense)
   support is another plus!

1. B2R2 is *OS-Independent*: it works on Linux, Mac, Windows, and etc. as long
   as .NET core supports it.

1. B2R2 is *interoperable*: it is not bound to a specific
   language. Theoretically, you can use B2R2 APIs with any [CLI supported
   languages](https://en.wikipedia.org/wiki/List_of_CLI_languages).

Features?
---------

B2R2 supports instruction parsing, binary disassembly, assembly, control-flow
recovery, and many more. B2R2 also comes with several user-level command-line
tools that are similar to readelf and objdump, although our tools are
platform-agnostic. B2R2 currently supports four binary file formats: ELF, PE,
Mach-O, and WebAssembly.

Below is a list of features that we currently support. Some of them are work in
progress, but we look forward to your contributions! Feel free to write a PR
(Pull Request) while making sure that you have read our [contribution
guideline](CONTRIBUTING.md).

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
    <td align="center">:first_quarter_moon:</td>
    <td align="center">:full_moon:</td>
    <td align="center">:full_moon:</td>
    <td align="center">:full_moon:</td>
    <td align="center">:full_moon:</td>
    <td align="center">:full_moon:</td>
  </tr>
  <tr>
    <td><b>x86-64</b></td>
    <td align="center">:first_quarter_moon:</td>
    <td align="center">:full_moon:</td>
    <td align="center">:full_moon:</td>
    <td align="center">:full_moon:</td>
    <td align="center">:full_moon:</td>
    <td align="center">:full_moon:</td>
  </tr>
  <tr>
    <td><b>ARMv7</b></td>
    <td align="center">:first_quarter_moon:</td>
    <td align="center">:full_moon:</td>
    <td align="center">:full_moon:</td>
    <td align="center">:full_moon:</td>
    <td align="center">:first_quarter_moon:</td>
    <td align="center">:new_moon:</td>
  </tr>
  <tr>
    <td><b>ARMv8 (AArch64)</b></td>
    <td align="center">:first_quarter_moon:</td>
    <td align="center">:full_moon:</td>
    <td align="center">:full_moon:</td>
    <td align="center">:full_moon:</td>
    <td align="center">:first_quarter_moon:</td>
    <td align="center">:new_moon:</td>
  </tr>
  <tr>
    <td><b>MIPS32</b></td>
    <td align="center">:first_quarter_moon:</td>
    <td align="center">:full_moon:</td>
    <td align="center">:full_moon:</td>
    <td align="center">:full_moon:</td>
    <td align="center">:first_quarter_moon:</td>
    <td align="center">:new_moon:</td>
  </tr>
  <tr>
    <td><b>MIPS64</b></td>
    <td align="center">:first_quarter_moon:</td>
    <td align="center">:full_moon:</td>
    <td align="center">:full_moon:</td>
    <td align="center">:full_moon:</td>
    <td align="center">:first_quarter_moon:</td>
    <td align="center">:new_moon:</td>
  </tr>
  <tr>
    <td><b>EVM</b></td>
    <td align="center">:first_quarter_moon:</td>
    <td align="center">:full_moon:</td>
    <td align="center">:full_moon:</td>
    <td align="center">:full_moon:</td>
    <td align="center">:first_quarter_moon:</td>
    <td align="center">:new_moon:</td>
  </tr>
  <tr>
    <td><b>TMS320C6000</b></td>
    <td align="center">:first_quarter_moon:</td>
    <td align="center">:full_moon:</td>
    <td align="center">:full_moon:</td>
    <td align="center">:new_moon:</td>
    <td align="center">:first_quarter_moon:</td>
    <td align="center">:new_moon:</td>
  </tr>
  <tr>
    <td><b>AVR</b></td>
    <td align="center">:first_quarter_moon:</td>
    <td align="center">:full_moon:</td>
    <td align="center">:full_moon:</td>
    <td align="center">:full_moon:</td>
    <td align="center">:first_quarter_moon:</td>
    <td align="center">:new_moon:</td>
  </tr>
  <tr>
    <td><b>PA-RISC</b></td>
    <td align="center">:first_quarter_moon:</td>
    <td align="center">:full_moon:</td>
    <td align="center">:full_moon:</td>
    <td align="center">:new_moon:</td>
    <td align="center">:first_quarter_moon:</td>
    <td align="center">:new_moon:</td>
  </tr>
  <tr>
    <td><b>PPC32</b></td>
    <td align="center">:first_quarter_moon:</td>
    <td align="center">:full_moon:</td>
    <td align="center">:full_moon:</td>
    <td align="center">:full_moon:</td>
    <td align="center">:first_quarter_moon:</td>
    <td align="center">:new_moon:</td>
  </tr>
  <tr>
    <td><b>SPARC</b></td>
    <td align="center">:first_quarter_moon:</td>
    <td align="center">:full_moon:</td>
    <td align="center">:full_moon:</td>
    <td align="center">:full_moon:</td>
    <td align="center">:first_quarter_moon:</td>
    <td align="center">:new_moon:</td>
  </tr>
  <tr>
    <td><b>SH4</b></td>
    <td align="center">:first_quarter_moon:</td>
    <td align="center">:full_moon:</td>
    <td align="center">:full_moon:</td>
    <td align="center">:new_moon:</td>
    <td align="center">:first_quarter_moon:</td>
    <td align="center">:new_moon:</td>
  </tr>
  <tr>
    <td><b>RISC-V</b></td>
    <td align="center">:first_quarter_moon:</td>
    <td align="center">:full_moon:</td>
    <td align="center">:full_moon:</td>
    <td align="center">:full_moon:</td>
    <td align="center">:first_quarter_moon:</td>
    <td align="center">:new_moon:</td>
  </tr>
  <tr>
    <td><b>S390</b></td>
    <td align="center">:first_quarter_moon:</td>
    <td align="center">:full_moon:</td>
    <td align="center">:full_moon:</td>
    <td align="center">:new_moon:</td>
    <td align="center">:first_quarter_moon:</td>
    <td align="center">:new_moon:</td>
  </tr>
</table>

Dependencies?
-------------

B2R2 relies on a tiny set of external .NET libraries, and our design principle
is to use a minimum number of libraries. Below is a list of libraries that we
leverage.

- [System.Reflection.Metadata](https://www.nuget.org/packages/System.Reflection.Metadata)
- [System.IO.Hashing](https://www.nuget.org/packages/System.IO.Hashing)
- [Microsoft.FSharpLu.Json](https://www.nuget.org/packages/Microsoft.FSharpLu.Json)
- [FSharp.Compiler.Service](https://www.nuget.org/packages/FSharp.Compiler.Service)
- [FParsec](https://www.nuget.org/packages/FParsec)
- [BenchmarkDotNet](https://www.nuget.org/packages/BenchmarkDotNet/)

API Documentation
-----------------

We currently use [fsdocs](https://github.com/fsprojects/FSharp.Formatting/) to
generate our documentation: https://b2r2.org/B2R2/.

Example
-------

Let's try to use B2R2 APIs.

1. First we create an empty directory `DIRNAME`:

    ```
    mkdir DIRNAME
    cd DIRNAME
    ```

1. We then create an empty console project with `dotnet` command line:

    ```
    $ dotnet new console -lang F#
    ```

1. Add our nuget package *B2R2.FrontEnd* to the project:

    ```
    $ dotnet add package B2R2.FrontEnd.API
    ```

1. Modify the `Program.fs` file with your favorite editor as follows:

    ```fsharp
    open B2R2
    open B2R2.FrontEnd

    [<EntryPoint>]
    let main argv =
      let isa = ISA.OfString "amd64"
      let bytes = [| 0x65uy; 0xffuy; 0x15uy; 0x10uy; 0x00uy; 0x00uy; 0x00uy |]
      let hdl = BinHandle (bytes, isa)
      let lifter = hdl.NewLiftingUnit ()
      let ins = lifter.ParseInstruction 0UL // parse the instruction at offset 0
      lifter.LiftInstruction ins |> printfn "%A"
      0
    ```

1. We then just run it by typing: `dotnet run`. You will be able see lifted IR
   statements from your console. That's it! You just lifted an Intel instruction
   with only few lines of F# code!

Build
-----

Building B2R2 is fun and easy. All you need to do is to install .NET 9 SDK or
above. Yea, that's it!

- To build B2R2 in release mode, type ```dotnet build -c Release``` in the
  source root.

- To build B2R2 in debug mode, type ```dotnet build``` in the source root.

For your information, please visit the official web site of F# to get more tips
about installing the development environment for F#: http://fsharp.org/.

Credits
-------

Members in [SoftSec Lab](https://softsec.kaist.ac.kr/). @ KAIST developed B2R2
in collaboration with [Cyber Security Research Center](http://csrc.kaist.ac.kr/)
(CSRC) at KAIST. See [Authors](AUTHORS.md) for the full list.

Citation
--------

If you plan to use B2R2 in your own research. Please consider citing our
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

Here are papers using our work. Please create a PR if you want to add yours.

- Towards Sound Reassembly of Modern x86-64 Binaries, ASPLOS 2025 [(PDF)](https://softsec.kaist.ac.kr/~sangkilc/papers/kim-asplos25.pdf)
- PoE: A Domain-Specific Language for Exploitation, SVCC 2024 [(PDF)](https://softsec.kaist.ac.kr/~sangkilc/papers/kim-svcc24.pdf)
- FunProbe: Probing Functions from Binary Code through Probabilistic Analysis, FSE 2023 [(PDF)](https://softsec.kaist.ac.kr/~sangkilc/papers/kim-fse23.pdf)
- How'd Security Benefit Reverse Engineers? The Implication of Intel CET on Function Identification, DSN 2022 [(PDF)](https://softsec.kaist.ac.kr/~sangkilc/papers/kim-dsn2022.pdf)
- Smartian: Enhancing Smart Contract Fuzzing with Static and Dynamic Data-Flow Analyses, ASE 2021 [(PDF)](https://softsec.kaist.ac.kr/~jschoi/data/ase2021.pdf)
- NTFuzz: Enabling Type-Aware Kernel Fuzzing on Windows with Static Binary Analysis, Oakland 2021 [(PDF)](https://softsec.kaist.ac.kr/~jschoi/data/oakland2021.pdf)
