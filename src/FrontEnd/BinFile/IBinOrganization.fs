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

namespace B2R2.FrontEnd.BinFile

open System.Runtime.InteropServices
open B2R2

/// Represents an interface for accessing the binary file organization, such as
/// sections, segments, and functions.
type IBinOrganization =
  /// <summary>
  ///   Return a list of all the sections from the binary.
  /// </summary>
  /// <returns>
  ///   An array of sections.
  /// </returns>
  abstract GetSections: unit -> Section[]

  /// <summary>
  ///   Return a section that contains the given address.
  /// </summary>
  /// <param name="addr">The address that belongs to a section.</param>
  /// <returns>
  ///   An array of sections that contain the given address. This function
  ///   returns an empty array if there is no section that contains the given
  ///   address.
  /// </returns>
  abstract GetSections: addr: Addr -> Section[]

  /// <summary>
  ///   Return a section that has the specified name.
  /// </summary>
  /// <param name="name">The name of the section.</param>
  /// <returns>
  ///   An array of sections that have the specified name. This function returns
  ///   an empty array if there is no section of the given name.
  /// </returns>
  abstract GetSections: name: string -> Section[]

  /// <summary>
  ///   Return a text section from the binary. If there's no text section, this
  ///   function raises an exception.
  /// </summary>
  /// <returns>
  ///   An array of text sections.
  /// </returns>
  abstract GetTextSection: unit -> Section

  /// <summary>
  ///   Return a list of segments from the binary. If the isLoadable parameter
  ///   is true, it will only return a list of "loadable" segments. Otherwise,
  ///   it will return all possible segments. By default, this function returns
  ///   only loadable segments, e.g., PT_LOAD segment of ELF.
  /// </summary>
  /// <returns>
  ///   An array of segments.
  /// </returns>
  abstract GetSegments:
    [<Optional; DefaultParameterValue(true)>] isLoadable:bool
    -> Segment[]

  /// <summary>
  ///   Return a list of the segments from the binary, which contain the given
  ///   address.
  /// </summary>
  /// <param name="addr">The address that belongs to segments.</param>
  /// <returns>
  ///   An array of segments.
  /// </returns>
  abstract GetSegments: addr: Addr -> Segment[]

  /// <summary>
  ///   For a given permission, return a list of segments that satisfy the
  ///   permission. For a given "READ-only" permission, this function may return
  ///   a segment whose permission is "READABLE and WRITABLE", as an instance.
  /// </summary>
  /// <returns>
  ///   An array of segments.
  /// </returns>
  abstract GetSegments: Permission -> Segment[]

  /// <summary>
  ///   Returns an array of local function addresses (excluding external
  ///   functions) from a given BinFile. This function only considers addresses
  ///   that are certain.
  /// </summary>
  /// <returns>
  ///   An array of function addresses.
  /// </returns>
  abstract GetFunctionAddresses: unit -> Addr[]

  /// <summary>
  ///   Returns an array of local function addresses (excluding external
  ///   functions) from a given BinFile. If the argument is true, then this
  ///   funciton utilizes exception information of the binary to infer function
  ///   entries. Note that the inference process is not necessarily precise, so
  ///   this is really just an experimental feature, and will be removed in the
  ///   future.
  /// </summary>
  /// <returns>
  ///   An array of function addresses.
  /// </returns>
  abstract GetFunctionAddresses: bool -> Addr[]
