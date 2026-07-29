# B2R2.FrontEnd.API

### B2R2?

B2R2 is a fully managed binary analysis framework written in F#. It provides a
rich set of algorithms, functions, and tools for reverse engineering, program
analysis, and binary-level inspection.

### B2R2.FrontEnd.API Package?

`B2R2.FrontEnd.API` is the main interface for B2R2's front-end. In most
cases, it should suffice to import just this package because all the other
front-end packages will be loaded by this one.

### Using it from C# or Visual Basic

B2R2 is written in F#, and its API is F#-first: part of the surface is typed
with F# types, which other .NET languages can consume but not idiomatically.
Two shapes account for nearly all of it.

- A member named `TryX` returns `FSharpResult<_, ErrorCase>`. Read `IsOk`
  first, then `ResultValue` or `ErrorValue`. `BinHandle.TryReadBytes` and
  `LiftingUnit.TryParseInstruction` are examples.
- An optional value is an `FSharpOption<_>`, which neither `?.` nor `??`
  reaches through. Test it with `OptionModule.IsSome(x)` before reading
  `x.Value`. This covers the optional base address the loaders take, and most
  of what `BinHandle.File` exposes, such as `EntryPoint`, `SymbolTable`, and
  `NameResolver`.

Both need `using Microsoft.FSharp.Core;` (`Imports Microsoft.FSharp.Core` in
Visual Basic). No extra package reference is required: FSharp.Core comes along
with this one. The samples under `samples/` show each shape.
