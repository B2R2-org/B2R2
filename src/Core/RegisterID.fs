(*
  B2R2 - the Next-Generation Reversing Platform

  Copyright (c) SoftSec Lab. @ KAIST, since 2016

  Permission is hereby granted, free of charge, to any person obtaining a copy
  of this software and associated documentation files (the "Software"), to deal
  in the Software without restriction, including without limitation the rights
  to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
  copies of the Software, and to permit persons to whom the Software is
  furnished to do so, subject to the following conditions:

  The above copyright notice and this permission notice shall be included in all
  copies or substantial portions of the Software.

  THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
  IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
  FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
  AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
  LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
  OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
  SOFTWARE.
*)

namespace B2R2

/// <summary>
/// Provides a function to create a <see cref='T:B2R2.RegisterID'/>. Although
/// it is essentially an integer, we internally use a "unit of measure" to
/// represent it, meaning that one needs to go through this module in order to
/// create a new ID.
/// </summary>
[<RequireQualifiedAccess>]
module RegisterID =

  /// A unit for register IDs.
  [<Measure>] type private T

  /// Create a platform-independent register ID representation.
  [<CompiledName "Create">]
  let inline create n: int<T> = LanguagePrimitives.Int32WithMeasure(n)

/// <summary>
/// Represents a platform-independent identifier for a register.
/// </summary>
type RegisterID = int<RegisterID.T>
