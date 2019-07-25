(*
  B2R2 - the Next-Generation Reversing Platform

  Author: Sang Kil Cha <sangkilc@kaist.ac.kr>

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

namespace B2R2.NameMangling.Tests

open Microsoft.VisualStudio.TestTools.UnitTesting
open B2R2.NameMangling.Tests.TestLib

[<TestClass>]
type ItaniumTests () =

  [<TestMethod>]
  member __.``ItaniumDemangler: Simple Function``() =
    let mangled = "_Z4funcibc"
    let result = "func(int, bool, char)"
    test mangled result

  [<TestMethod>]
  member __.``ItaniumDemangler: Simple Function, CV qualifiers 1 ``() =
    let mangled = "_Z4funcPKibPVc"
    let result = "func(int const*, bool, char volatile*)"
    test mangled result

  [<TestMethod>]
  member __.``ItaniumDemangler: Simple Function, CV qualifiers 2 ``() =
    let mangled = "_Z4funcPVKibPVKPc"
    let result = "func(int const volatile*, bool, char* const volatile*)"
    test mangled result

  [<TestMethod>]
  member __.``ItaniumDemangler: Simple Function, Reference qualifiers ``() =
    let mangled = "_Z4funcRibOVc"
    let result = "func(int&, bool, char volatile&&)"
    test mangled result

  [<TestMethod>]
  member __.``ItaniumDemangler: Simple Function,  Qualifiers ``() =
    let mangled = "_Z4funcRVPVKPibOKPc"
    let result = "func(int* const volatile* volatile&, bool, char* const&&)"
    test mangled result

  [<TestMethod>]
  member __.``ItaniumDemangler: Nested Names``() =
    let mangled = "_ZN5first6second5thirdE"
    let result = "first::second::third"
    test mangled result

  [<TestMethod>]
  member __.``ItaniumDemangler: Nested Names with arguments``() =
    let mangled = "_ZN5first6second5thirdEidb3arg"
    let result = "first::second::third(int, double, bool, arg)"
    test mangled result

  [<TestMethod>]
  member __.``ItaniumDemangler: Simple Templates``() =
    let mangled = "_Z9somethingI3argifE"
    let result = "something<arg, int, float>"
    test mangled result

  [<TestMethod>]
  member __.``ItaniumDemangler: Template Arguments with qualifiers``() =
    let mangled = "_Z9somethingIPV3argRKiPVPfE"
    let result = "something<arg volatile*, int const&, float* volatile*>"
    test mangled result

  [<TestMethod>]
  member __.``ItaniumDemangler: Templates with return``() =
    let mangled = "_Z9somethingIPV3argRKiPVPfEPVibc"
    let result = "int volatile* something<arg volatile*, int const&, \
    float* volatile*>(bool, char)"
    test mangled result
