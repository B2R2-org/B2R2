B2R2
====

B2R2 is a collection of useful algorithms, functions, and tools for **binary
analysis**, written purely in F# (in .NET lingo, it is purely managed code).
B2R2 has been named after [R2-D2](https://en.wikipedia.org/wiki/R2-D2), a famous
fictional robot appeared in the Star Wars. In fact, B2R2's original name was
*B2-R2*, but we decided to use the name *B2R2* instead, because .NET does not
allow dash (-) characters in identifiers (or namespaces). The name essentially
represents "binary" or "two". Note that "binary" itself means "two" states
anyways. "B" and "2" mean "binary", and "R" means *reversing*.

N.B.
----

This is a prerelease of B2R2. We currently only open the [Nuget
access](https://www.nuget.org/packages/B2R2.FrontEnd/) for our front-end. We
will make our source code fully public before the [NDSS
BAR](https://www.ndss-symposium.org/ndss2019/cfp-bar-2019/) workshop begins!


B2R2?
-----

1. B2R2 is *analysis-friendly*: it is written in F#, which provides all the
   syntactic goodies for writing program analyzers, such as pattern matching,
   algebraic data types, and etc.

1. B2R2 is *fast*: it has a fast and efficient front-end engine for binary
   analysis, which is written purely in a functional way. Therefore, it
   naturally supports *pure parallelism* for binary disassembling, lifting and
   IR optimization.

1. B2R2 is *easy* to play with: there is absolutely no dependency hell for B2R2:
   All you need to do is to install [.NET Core
   SDK](https://dotnet.microsoft.com/download), and you are ready to go! Native
   [IntelliSense](https://docs.microsoft.com/en-us/visualstudio/ide/using-intellisense?view=vs-2017)
   support is another plus!

1. B2R2 is *OS-Independent*: it works on Linux, Mac, Windows, and etc. as long
   as .NET core supports it.

1. B2R2 is *interoperable*: it is not bound to a specific
   language. Theoretically, you can use B2R2 APIs with any [CLI supported
   languages](https://en.wikipedia.org/wiki/List_of_CLI_languages).

Dependencies?
-------------

B2R2 itself does *not* rely on any external libraries. But, one of our utilities
leverages [Gui.cs](https://github.com/migueldeicaza/gui.cs/) to represent
command-line interfaces in a platform-independent manner. Gui.cs internally uses
the *libcurses* library on &ast;nix system, which is indeed a default library in
most Linux distros or in macOS. So, you really don't need to install any other
libraries in order to build B2R2!

Why Reinventing the Wheel?
--------------------------

There are many other great tools available, but we wanted to build a
*functional-first* binary analysis platform that is painless to install and runs
on any platform without any hassle. B2R2 is in its *infancy* stage, but we
believe it provides a rich set of library functions for binary analysis. It also
has a strong front-end that is easily adaptable and extendible! Currently it
reliably supports x86 and x86-64, meaning that we have heavily tested them; and
it partially supports ARMv7 (and Thumb), ARMv8, MIPS32, and MIPS64, meaning that
they work, but we haven't tested them thoughly yet.

Example
-------

Let's try to use B2R2 APIs.

1. First we create an empty directory `DIRNAME`:

    ```
    mkdir DIRNAME
    ```

1. We then create an empty console project with `dotnet` command line:

    ```
    $ dotnet new console -lang F#
    ```

1. Add our nuget package *B2R2.FrontEnd* to the project:

    ```
    $ dotnet add package B2R2.FrontEnd --version 0.1.0-alpha
    ```

1. Modify the `Program.fs` file with your favorite editor as follows:

    ```fsharp
    open B2R2
    open B2R2.FrontEnd

    [<EntryPoint>]
    let main argv =
      let isa = ISA.OfString "amd64"
      let bytes = [| 0x65uy; 0xffuy; 0x15uy; 0x10uy; 0x00uy; 0x00uy; 0x00uy |]
      let handler = BinHandler.Init (isa, bytes)
      let ins = BinHandler.ParseInstr handler 0UL
      ins.Translate handler.TranslationContext |> printfn "%A"
      0
    ```

1. We then just run it by typing: `dotnet run`. You will be able see lifted IR
   statements from your console. That's it! You just lifted an Intel instruction
   with only few lines of F# code!

Build
-----

Building B2R2 is fun and easy. All you need to do is to install .NET Core SDK
2.0 or above. Yea, that's it!

- To build B2R2 in release mode, type ```make release``` or ```dotnet build -c
  Release``` in the source root.

- To build B2R2 in debug mode, type ```make```, or ```dotnet build``` in the
  source root.

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
[paper](https://FIXME):

```bibtex
@INPROCEEDINGS{jung:bar:2019,
  author = {Minkyu Jung and Soomin Kim and HyungSeok Han and Jaeseung Choi and Sang Kil Cha},
  title = {{B2R2}: Building an Efficient Front-End for Binary Analysis},
  booktitle = {Proceedings of the NDSS Workshop on Binary Analysis Research},
  year = 2019
}
```
