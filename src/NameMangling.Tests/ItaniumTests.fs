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

  [<TestMethod>]
  member __.``ItaniumDemangler: Array Pointer``() =
    let mangled = "_Z4funcPA30_A40_Pi"
    let result = "func(int* [30][40])"
    test mangled result

  [<TestMethod>]
  member __.``ItaniumDemangler: Literals inside Template``() =
    let mangled = "_Z4funcILi42ELb3ELb0EE"
    let result = "func<42, true, false>"
    test mangled result

  [<TestMethod>]
  member __.``ItaniumDemangler: Nested Names And Templates 1``() =
    let mangled = "_ZN4some3anyIibcE4funcE"
    let result = "some::any<int, bool, char>::func"
    test mangled result

  [<TestMethod>]
  member __.``ItaniumDemangler: Nested Names And Templates 2``() =
    let mangled = "_ZN4some3anyI4arg1N4name5classEE4funcE"
    let result = "some::any<arg1, name::class>::func"
    test mangled result

  [<TestMethod>]
  member __.``ItaniumDemangler: Nested Names And Templates 3``() =
    let mangled = "_ZN5funcA5funcBI4arg1N5funcC5funcDI4arg2EE4arg3E5funcEE"
    let result = "funcA::funcB<arg1, funcC::funcD<arg2>, arg3>::funcE"
    test mangled result

  [<TestMethod>]
  member __.``ItaniumDemangler: Nested Names Constructors, Destructors 1``() =
    let mangled = "_ZN5funcA5funcBI4arg1icEC1E"
    let result = "funcA::funcB<arg1, int, char>::funcB"
    test mangled result

  [<TestMethod>]
  member __.``ItaniumDemangler: Nested Names Constructors, Destructors 2``() =
    let mangled = "_ZN5funcA5funcBI4arg1icE5funcCD1E"
    let result = "funcA::funcB<arg1, int, char>::funcC::~funcC"
    test mangled result

  [<TestMethod>]
  member __.``ItaniumDemangler: Nested Names, Return and Arguments``() =
    let mangled = "_ZN5funcA5funcBI4arg1dsEERVK5funcCIiEPKbi"
    let result = "funcC<int> const volatile& funcA::funcB<arg1, double, short>\
    (bool const*, int)"
    test mangled result

  [<TestMethod>]
  member __.``ItaniumDemangler: Function Pointers``() =
    let mangled = "_Z4funcPFicE"
    let result = "func(int (*)(char))"
    test mangled result

  [<TestMethod>]
  member __.``ItaniumDemangler: Nested Function Pointers``() =
    let mangled = "_Z4funcPFPFPFicEbEdE"
    let result = "func(int (*(*(*)(double))(bool))(char))"
    test mangled result

  [<TestMethod>]
  member __.``ItaniumDemangler: Function Pointers with qualifiers``() =
    let mangled = "_Z4funcPKPFPrVPPFPFicEbEdE"
    let result =
      "func(int (*(** volatile __restrict__*(* const*)(double))(bool))(char))"
    test mangled result

  [<TestMethod>]
  member __.``ItaniumDemangler: Binary Operator inside Templates``() =
    let mangled = "_ZN5funcA5funcB5funcCI4arg1EEi5funcDIXpl4arg24arg3EE"
    let result = "int funcA::funcB::funcC<arg1>(funcD<(arg2)+(arg3)>)"
    test mangled result

  [<TestMethod>]
  member __.``ItaniumDemangler: Unary Operator inside Templates``() =
    let mangled = "_Z5funcAIRVPKiEPbN5funcB5funcCIXad5funcDIPcEEEE"
    let result =
      "bool* funcA<int const* volatile&>(funcB::funcC<&(funcD<char*>)>)"
    test mangled result

  [<TestMethod>]
  member __.``ItaniumDemangler: Nested Expression inside Templates``() =
    let mangled = "_Z5funcAIXntaaLb42ELb0EEE"
    let result = "funcA<!((true)&&(false))>"
    test mangled result

  [<TestMethod>]
  member __.``ItaniumDemangler: Sx abbreviation 1``() =
    let mangled = "_ZNSo5funcA5funcBE"
    let result =
      "std::basic_ostream<char, std::char_traits<char>>::funcA::funcB"
    test mangled result

  [<TestMethod>]
  member __.``ItaniumDemangler: Sx abbreviation 2``() =
    let mangled = "_ZSt5funcAIPiPrKP5funcBIPiEE"
    let result = "std::funcA<int*, funcB<int*>* const __restrict__*>"
    test mangled result

  [<TestMethod>]
  member __.``ItaniumDemangler: General Substitution 1``() =
    let mangled = "_ZN5funcA5funcB5funcCIN5funcD5funcEEE5funcFES2_S4_"
    let result = "funcA::funcB::funcC<funcD::funcE>::funcF(funcD, funcA::\
    funcB::funcC<funcD::funcE>)"
    test mangled result

  [<TestMethod>]
  member __.``ItaniumDemangler: General Substitution 2``() =
    let mangled = "_Z5funcAPVKPKiRKbPV4arg1S0_S4_S5_"
    let result = "funcA(int const* const volatile*, bool const&, arg1 \
    volatile*, int const*, bool const&, arg1)"
    test mangled result

  [<TestMethod>]
  member __.``ItaniumDemangler: Template Substitution``() =
    let mangled = "_Z5funcAI4arg1iPKb4arg2IcEEiT_T0_T2_"
    let result = "int funcA<arg1, int, bool const*, arg2<char>>\
    (arg1, int, arg2<char>)"
    test mangled result

  [<TestMethod>]
  member __.``ItaniumDemangler: Complex Test 1``() =
    let mangled = "_ZN9__gnu_cxx17__normal_iteratorIPSt4pairIiiESt6vectorIS2\
    _SaIS2_EEEC1ERKS3_"
    let result = "__gnu_cxx::__normal_iterator<std::pair<int, int>*, \
    std::vector<std::pair<int, int>, std::allocator\
    <std::pair<int, int>>>>::__normal_iterator(std::pair<int, int>* const&)"
    test mangled result

  [<TestMethod>]
  member __.``ItaniumDemangler: Complex Test 2``() =
    let mangled = "_ZN9__gnu_cxxmiIPSt4pairIiiESt6vectorIS2_SaIS2_EEEENS_17__\
    normal_iteratorIT_T0_E15difference_typeERKSA_SD_"
    let result = "__gnu_cxx::__normal_iterator<std::pair<int, int>*, \
    std::vector<std::pair<int, int>, std::allocator<std::pair<int, int>>>>::\
    difference_type __gnu_cxx::operator-<std::pair<int, int>*, \
    std::vector<std::pair<int, int>, std::allocator<std::pair<int, int>>>>\
    (__gnu_cxx::__normal_iterator<std::pair<int, int>*, std::vector\
    <std::pair<int, int>, std::allocator<std::pair<int, int>>>> const&, __gnu\
    _cxx::__normal_iterator<std::pair<int, int>*, std::vector<std::pair\
    <int, int>, std::allocator<std::pair<int, int>>>> const&)"
    test mangled result

  [<TestMethod>]
  member __.``ItaniumDemangler: Complex Test 3``() =
    let mangled = "_ZSt4swapIPSt3mapIixSt4lessIiESaISt4pairIKixEEEENSt9enable\
    _ifIXsrSt6__and_IJSt21is_move_constructibleIT_ESt18is_move_assignableISC_\
    EEE5valueEvE4typeERSC_SJ_"
    let result = "std::enable_if<std::__and_<std::is_move_constructible\
    <std::map<int, long long, std::less<int>, std::allocator<std::pair<int \
    const, long long>>>*>, std::is_move_assignable<std::map<int, long long, \
    std::less<int>, std::allocator<std::pair<int const, long long>>>*>>::\
    value, void>::type std::swap<std::map<int, long long, std::less<int>, std\
    ::allocator<std::pair<int const, long long>>>*>(std::map<int, long long, \
    std::less<int>, std::allocator<std::pair<int const, long long>>>*&, std::\
    map<int, long long, std::less<int>, std::allocator<std::pair<int const, \
    long long>>>*&)"
    test mangled result


