namespace B2R2.Assembly.Tests

open System
open System.IO
open Microsoft.VisualStudio.TestTools.UnitTesting

module MSTestSettings =

  (* One sweep per architecture, and each is a run of the decoder over a space
     of its own that shares nothing with the others, so they run at the same
     time. Within a class the tests stay in order, because the parser a class
     holds carries state from one instruction to the next. *)
  [<assembly: Parallelize(Scope = ExecutionScope.ClassLevel)>]

  do ()

/// <summary>
/// Mutes stderr for the whole run.
///
/// Terminator.futureFeature writes a stack trace there for every opcode an
/// assembler has yet to cover, which would bury the actual test output. Each
/// class mutes it around its own sweep as well, but saving and restoring the
/// writer is not something two of them can do at once: one restores what
/// another had already replaced, so a sweep runs with stderr open and spills
/// its traces. Muting it once here leaves each of those with nothing to change.
/// </summary>
[<TestClass>]
type MSTestHooks() =

  [<AssemblyInitialize>]
  static member Initialize(_: TestContext) = Console.SetError TextWriter.Null
