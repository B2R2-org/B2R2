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

namespace B2R2.FrontEnd.NameMangling.Tests

open Microsoft.VisualStudio.TestTools.UnitTesting
open B2R2.FrontEnd.NameMangling

[<TestClass>]
type ItaniumDemanglerTests() =

  [<TestMethod>]
  member _.``ItaniumDemangler: Simple Function``() =
    let mangled = "_Z4funcibc"
    let result = "func(int, bool, char)"
    Assert.Correct(mangled, result, ItaniumDemangler())

  [<TestMethod>]
  member _.``ItaniumDemangler: Simple Function, CV qualifiers 1 ``() =
    let mangled = "_Z4funcPKibPVc"
    let result = "func(int const*, bool, char volatile*)"
    Assert.Correct(mangled, result, ItaniumDemangler())

  [<TestMethod>]
  member _.``ItaniumDemangler: Simple Function, CV qualifiers 2 ``() =
    let mangled = "_Z4funcPVKibPVKPc"
    let result = "func(int const volatile*, bool, char* const volatile*)"
    Assert.Correct(mangled, result, ItaniumDemangler())

  [<TestMethod>]
  member _.``ItaniumDemangler: Simple Function, Reference qualifiers ``() =
    let mangled = "_Z4funcRibOVc"
    let result = "func(int&, bool, char volatile&&)"
    Assert.Correct(mangled, result, ItaniumDemangler())

  [<TestMethod>]
  member _.``ItaniumDemangler: Simple Function,  Qualifiers ``() =
    let mangled = "_Z4funcRVPVKPibOKPc"
    let result = "func(int* const volatile* volatile&, bool, char* const&&)"
    Assert.Correct(mangled, result, ItaniumDemangler())

  [<TestMethod>]
  member _.``ItaniumDemangler: Nested Names``() =
    let mangled = "_ZN5first6second5thirdE"
    let result = "first::second::third"
    Assert.Correct(mangled, result, ItaniumDemangler())

  [<TestMethod>]
  member _.``ItaniumDemangler: Nested Names with arguments``() =
    let mangled = "_ZN5first6second5thirdEidb3arg"
    let result = "first::second::third(int, double, bool, arg)"
    Assert.Correct(mangled, result, ItaniumDemangler())

  [<TestMethod>]
  member _.``ItaniumDemangler: Simple Templates``() =
    let mangled = "_Z9somethingI3argifE"
    let result = "something<arg, int, float>"
    Assert.Correct(mangled, result, ItaniumDemangler())

  [<TestMethod>]
  member _.``ItaniumDemangler: Template Arguments with qualifiers``() =
    let mangled = "_Z9somethingIPV3argRKiPVPfE"
    let result = "something<arg volatile*, int const&, float* volatile*>"
    Assert.Correct(mangled, result, ItaniumDemangler())

  [<TestMethod>]
  member _.``ItaniumDemangler: Templates with return``() =
    let mangled = "_Z9somethingIPV3argRKiPVPfEPVibc"
    let result = "int volatile* something<arg volatile*, int const&, \
    float* volatile*>(bool, char)"
    Assert.Correct(mangled, result, ItaniumDemangler())

  [<TestMethod>]
  member _.``ItaniumDemangler: Array Pointer``() =
    let mangled = "_Z4funcPA30_A40_Pi"
    let result = "func(int* (*) [30][40])"
    Assert.Correct(mangled, result, ItaniumDemangler())

  [<TestMethod>]
  member _.``ItaniumDemangler: Literals inside Template``() =
    let mangled = "_Z4funcILi42ELb3ELb0EE"
    let result = "func<42, true, false>"
    Assert.Correct(mangled, result, ItaniumDemangler())

  [<TestMethod>]
  member _.``ItaniumDemangler: Nested Names And Templates 1``() =
    let mangled = "_ZN4some3anyIibcE4funcE"
    let result = "some::any<int, bool, char>::func"
    Assert.Correct(mangled, result, ItaniumDemangler())

  [<TestMethod>]
  member _.``ItaniumDemangler: Nested Names And Templates 2``() =
    let mangled = "_ZN4some3anyI4arg1N4name5classEE4funcE"
    let result = "some::any<arg1, name::class>::func"
    Assert.Correct(mangled, result, ItaniumDemangler())

  [<TestMethod>]
  member _.``ItaniumDemangler: Nested Names And Templates 3``() =
    let mangled = "_ZN5funcA5funcBI4arg1N5funcC5funcDI4arg2EE4arg3E5funcEE"
    let result = "funcA::funcB<arg1, funcC::funcD<arg2>, arg3>::funcE"
    Assert.Correct(mangled, result, ItaniumDemangler())

  [<TestMethod>]
  member _.``ItaniumDemangler: Nested Names Constructors, Destructors 1``() =
    let mangled = "_ZN5funcA5funcBI4arg1icEC1E"
    let result = "funcA::funcB<arg1, int, char>::funcB"
    Assert.Correct(mangled, result, ItaniumDemangler())

  [<TestMethod>]
  member _.``ItaniumDemangler: Nested Names Constructors, Destructors 2``() =
    let mangled = "_ZN5funcA5funcBI4arg1icE5funcCD1E"
    let result = "funcA::funcB<arg1, int, char>::funcC::~funcC"
    Assert.Correct(mangled, result, ItaniumDemangler())

  [<TestMethod>]
  member _.``ItaniumDemangler: Nested Names, Return and Arguments``() =
    let mangled = "_ZN5funcA5funcBI4arg1dsEERVK5funcCIiEPKbi"
    let result = "funcC<int> const volatile& funcA::funcB<arg1, double, short>\
    (bool const*, int)"
    Assert.Correct(mangled, result, ItaniumDemangler())

  [<TestMethod>]
  member _.``ItaniumDemangler: Function Pointers``() =
    let mangled = "_Z4funcPFicE"
    let result = "func(int (*)(char))"
    Assert.Correct(mangled, result, ItaniumDemangler())

  [<TestMethod>]
  member _.``ItaniumDemangler: Nested Function Pointers``() =
    let mangled = "_Z4funcPFPFPFicEbEdE"
    let result = "func(int (*(*(*)(double))(bool))(char))"
    Assert.Correct(mangled, result, ItaniumDemangler())

  [<TestMethod>]
  member _.``ItaniumDemangler: Function Pointers with qualifiers``() =
    let mangled = "_Z4funcPKPFPrVPPFPFicEbEdE"
    let result =
      "func(int (*(** volatile __restrict__*(* const*)(double))(bool))(char))"
    Assert.Correct(mangled, result, ItaniumDemangler())

  [<TestMethod>]
  member _.``ItaniumDemangler: Binary Operator inside Templates``() =
    let mangled = "_ZN5funcA5funcB5funcCI4arg1EEi5funcDIXpl4arg24arg3EE"
    let result = "int funcA::funcB::funcC<arg1>(funcD<(arg2)+(arg3)>)"
    Assert.Correct(mangled, result, ItaniumDemangler())

  [<TestMethod>]
  member _.``ItaniumDemangler: Unary Operator inside Templates``() =
    let mangled = "_Z5funcAIRVPKiEPbN5funcB5funcCIXad5funcDIPcEEEE"
    let result =
      "bool* funcA<int const* volatile&>(funcB::funcC<&(funcD<char*>)>)"
    Assert.Correct(mangled, result, ItaniumDemangler())

  [<TestMethod>]
  member _.``ItaniumDemangler: Nested Expression inside Templates``() =
    let mangled = "_Z5funcAIXntaaLb42ELb0EEE"
    let result = "funcA<!((true)&&(false))>"
    Assert.Correct(mangled, result, ItaniumDemangler())

  [<TestMethod>]
  member _.``ItaniumDemangler: Sx abbreviation 1``() =
    let mangled = "_ZNSo5funcA5funcBE"
    let result =
      "std::basic_ostream<char, std::char_traits<char> >::funcA::funcB"
    Assert.Correct(mangled, result, ItaniumDemangler())

  [<TestMethod>]
  member _.``ItaniumDemangler: Sx abbreviation 2``() =
    let mangled = "_ZSt5funcAIPiPrKP5funcBIPiEE"
    let result = "std::funcA<int*, funcB<int*>* const __restrict__*>"
    Assert.Correct(mangled, result, ItaniumDemangler())

  [<TestMethod>]
  member _.``ItaniumDemangler: General Substitution 1``() =
    let mangled = "_ZN5funcA5funcB5funcCIN5funcD5funcEEE5funcFES2_S4_"
    let result = "funcA::funcB::funcC<funcD::funcE>::funcF(funcD, funcA::\
    funcB::funcC<funcD::funcE>)"
    Assert.Correct(mangled, result, ItaniumDemangler())

  [<TestMethod>]
  member _.``ItaniumDemangler: General Substitution 2``() =
    let mangled = "_Z5funcAPVKPKiRKbPV4arg1S0_S4_S5_"
    let result = "funcA(int const* const volatile*, bool const&, arg1 \
    volatile*, int const*, bool const&, arg1)"
    Assert.Correct(mangled, result, ItaniumDemangler())

  [<TestMethod>]
  member _.``ItaniumDemangler: Template Substitution``() =
    let mangled = "_Z5funcAI4arg1iPKb4arg2IcEEiT_T0_T2_"
    let result = "int funcA<arg1, int, bool const*, arg2<char> >\
    (arg1, int, arg2<char>)"
    Assert.Correct(mangled, result, ItaniumDemangler())

  [<TestMethod>]
  member _.``ItaniumDemangler: Complex Test 1``() =
    let mangled = "_ZN9__gnu_cxx17__normal_iteratorIPSt4pairIiiESt6vectorIS2\
    _SaIS2_EEEC1ERKS3_"
    let result = "__gnu_cxx::__normal_iterator<std::pair<int, int>*, \
    std::vector<std::pair<int, int>, std::allocator\
    <std::pair<int, int> > > >::__normal_iterator(std::pair<int, int>* const&)"
    Assert.Correct(mangled, result, ItaniumDemangler())

  [<TestMethod>]
  member _.``ItaniumDemangler: Complex Test 2``() =
    let mangled = "_ZN9__gnu_cxxmiIPSt4pairIiiESt6vectorIS2_SaIS2_EEEENS_17__\
    normal_iteratorIT_T0_E15difference_typeERKSA_SD_"
    let result = "__gnu_cxx::__normal_iterator<std::pair<int, int>*, \
    std::vector<std::pair<int, int>, std::allocator<std::pair<int, int> > > >::\
    difference_type __gnu_cxx::operator-<std::pair<int, int>*, \
    std::vector<std::pair<int, int>, std::allocator<std::pair<int, int> > > >\
    (__gnu_cxx::__normal_iterator<std::pair<int, int>*, std::vector\
    <std::pair<int, int>, std::allocator<std::pair<int, int> > > > const&, \
    __gnu_cxx::__normal_iterator<std::pair<int, int>*, std::vector<std::pair\
    <int, int>, std::allocator<std::pair<int, int> > > > const&)"
    Assert.Correct(mangled, result, ItaniumDemangler())

  [<TestMethod>]
  member _.``ItaniumDemangler: Complex Test 3``() =
    let mangled = "_ZSt4swapIPSt3mapIixSt4lessIiESaISt4pairIKixEEEENSt9enable\
    _ifIXsrSt6__and_IJSt21is_move_constructibleIT_ESt18is_move_assignableISC_\
    EEE5valueEvE4typeERSC_SJ_"
    let result = "std::enable_if<std::__and_<std::is_move_constructible\
    <std::map<int, long long, std::less<int>, std::allocator<std::pair<int \
    const, long long> > >*>, std::is_move_assignable<std::map<int, long long, \
    std::less<int>, std::allocator<std::pair<int const, long long> > >*> >::\
    value, void>::type std::swap<std::map<int, long long, std::less<int>, std\
    ::allocator<std::pair<int const, long long> > >*>(std::map<int, long long, \
    std::less<int>, std::allocator<std::pair<int const, long long> > >*&, std::\
    map<int, long long, std::less<int>, std::allocator<std::pair<int const, \
    long long> > >*&)"
    Assert.Correct(mangled, result, ItaniumDemangler())

  [<TestMethod>]
  member _.``ItaniumDemangler: RTTI and Virtual Table``() =
    let mangled = "_ZTI14GTKFDIOManager"
    let result = "typeinfo for GTKFDIOManager"
    Assert.Correct(mangled, result, ItaniumDemangler())

  [<TestMethod>]
  member _.``ItaniumDemangler: Clone``() =
    let mangled =
      "_ZN12wxAuiToolBar11OnRightDownER12wxMouseEvent.localalias.159"
    let result =
      "wxAuiToolBar::OnRightDown(wxMouseEvent&) [clone .localalias.159]"
    Assert.Correct(mangled, result, ItaniumDemangler())

  [<TestMethod>]
  member _.``ItaniumDemangler: Scope Encoding``() =
    let mangled =
      "_ZZN17wxBaseObjectArrayI16wxAuiToolBarItem43wxObjectArrayTraitsForwxAui\
      ToolBarItemArrayE8RemoveAtEmmE12__FUNCTION__"
    let result =
      "wxBaseObjectArray<wxAuiToolBarItem, wxObjectArrayTraitsForwxAuiToolBar\
      ItemArray>::RemoveAt(unsigned long, unsigned long)::__FUNCTION__"
    Assert.Correct(mangled, result, ItaniumDemangler())

  [<TestMethod>]
  member _.``ItaniumDemangler: Member Pointer``() =
    let mangled =
      "_ZNK16wxAppConsoleBase11HandleEventEP12wxEvtHandlerMS0_FvR7wxEventES3_"
    let result =
      "wxAppConsoleBase::HandleEvent(wxEvtHandler*, void (wxEvtHandler::*)\
      (wxEvent&), wxEvent&) const"
    Assert.Correct(mangled, result, ItaniumDemangler())

  [<TestMethod>]
  member _.``ItaniumDemangler: Anonymous namespace``() =
    let mangled =
      "_ZN9wxPrivate18wxVectorComparatorIN12_GLOBAL__N_117wxAuiLayoutObject\
      EE7CompareEPKvS5_S5_"
    let result =
      "wxPrivate::wxVectorComparator<(anonymous namespace)::wxAuiLayoutObject>\
      ::Compare(void const*, void const*, void const*)"
    Assert.Correct(mangled, result, ItaniumDemangler())

  [<TestMethod>]
  member _.``ItaniumDemangler: Scope Encoding: Return values``() =
    let mangled =
      "_ZZ11wxCheckCastI18wxAuiMDIChildFrameEPT_PKvE12__FUNCTION__"
    let result =
      "wxCheckCast<wxAuiMDIChildFrame>(void const*)::__FUNCTION__"
    Assert.Correct(mangled, result, ItaniumDemangler())

  [<TestMethod>]
  member _.``ItaniumDemangler: Guard Variables: Scope Encoding``() =
    let mangled =
      "_ZGVZN12_GLOBAL__N_113ParseFormatAtERN8wxString14const_iteratorERK\
      S1_RKS0_S6_E5dtDef"
    let result =
      "guard variable for (anonymous namespace)::ParseFormatAt(wxString::\
      const_iterator&, wxString::const_iterator const&, wxString const&, \
      wxString const&)::dtDef"
    Assert.Correct(mangled, result, ItaniumDemangler())

  [<TestMethod>]
  member _.``ItaniumDemangler: Scope Encoding: Discriminator values``() =
    let mangled = "_ZZL17wx_add_idle_hooksvE14hook_installed_0"
    let result = "wx_add_idle_hooks()::hook_installed"
    Assert.Correct(mangled, result, ItaniumDemangler())

  [<TestMethod>]
  member _.``ItaniumDemangler: RTTI values: TC``() =
    let mangled = "_ZTC17wxStdOutputStream0_So"
    let result =
      "construction vtable for std::basic_ostream<char, std::char_traits<char> \
      >-in-wxStdOutputStream"
    Assert.Correct(mangled, result, ItaniumDemangler())

  [<TestMethod>]
  member _.``ItaniumDemangler: Pointer to Member Function as Argument``() =
    let mangled =
      "_ZN9OptionSetIN12_GLOBAL__N_111OptionsBaanEE14DefinePropertyEPKcMS1_bN\
      St7__cxx1112basic_stringIcSt11char_traitsIcESaIcEEE"
    let result =
      "OptionSet<(anonymous namespace)::OptionsBaan>::DefineProperty\
      (char const*, bool (anonymous namespace)::OptionsBaan::*, std::__cxx11\
      ::basic_string<char, std::char_traits<char>, std::allocator<char> >)"
    Assert.Correct(mangled, result, ItaniumDemangler())

  [<TestMethod>]
  member _.``ItaniumDemangler: ABI Tags``() =
    let mangled = "_ZN8Document17TransformLineEndsB5cxx11EPKcmi"
    let result =
      "Document::TransformLineEnds[abi:cxx11](char const*, unsigned long, int)"
    Assert.Correct(mangled, result, ItaniumDemangler())

  [<TestMethod>]
  member _.``ItaniumDemangler: Cast Operator``() =
    let mangled = "_ZNK21wxArgNormalizedStringcv8wxStringEv"
    let result = "wxArgNormalizedString::operator wxString() const"
    Assert.Correct(mangled, result, ItaniumDemangler())

  [<TestMethod>]
  member _.``ItaniumDemangler: Template Substitution, Repeating variables``() =
    let mangled = "_ZN8wxString6PrintfIddddddddddddddddddddEEiRK14wxFormatStr\
    ingT_T0_T1_T2_T3_T4_T5_T6_T7_T8_T9_T10_T11_T12_T13_T14_T15_T16_T17_T18_"
    let result = "int wxString::Printf<double, double, double, double, double, \
    double, double, double, double, double, double, double, double, double, \
    double, double, double, double, double, double>(wxFormatString const&, \
    double, double, double, double, double, double, double, double, double, \
    double, double, double, double, double, double, double, double, double, \
    double, double)"
    Assert.Correct(mangled, result, ItaniumDemangler())

  [<TestMethod>]
  member _.``ItaniumDemangler: Argument Packs``() =
    let mangled = "_ZNSt8_Rb_treeINSt7__cxx1112basic_stringIcSt11char_traits\
    IcESaIcEEESt4pairIKS5_N9OptionSetI10OptionsAsmE6OptionEESt10_Select1stIS\
    C_ESt4lessIS5_ESaISC_EE22_M_emplace_hint_uniqueIJRKSt21piecewise_construc\
    t_tSt5tupleIJOS5_EESN_IJEEEEESt17_Rb_tree_iteratorISC_ESt23_Rb_tree_const\
    _iteratorISC_EDpOT_.isra.74"
    let result = "std::_Rb_tree_iterator<std::pair<std::__cxx11::basic_string\
    <char, std::char_traits<char>, std::allocator<char> > const, OptionSet\
    <OptionsAsm>::Option> > std::_Rb_tree<std::__cxx11::basic_string<char, \
    std::char_traits<char>, std::allocator<char> >, std::pair<std::__cxx11::\
    basic_string<char, std::char_traits<char>, std::allocator<char> > const, \
    OptionSet<OptionsAsm>::Option>, std::_Select1st<std::pair<std::__cxx11::\
    basic_string<char, std::char_traits<char>, std::allocator<char> > const, \
    OptionSet<OptionsAsm>::Option> >, std::less<std::__cxx11::basic_string\
    <char, std::char_traits<char>, std::allocator<char> > >, std::allocator\
    <std::pair<std::__cxx11::basic_string<char, std::char_traits<char>, \
    std::allocator<char> > const, OptionSet<OptionsAsm>::Option> > >::_M_\
    emplace_hint_unique<std::piecewise_construct_t const&, std::tuple<std::\
    __cxx11::basic_string<char, std::char_traits<char>, std::allocator<char> \
    >&&>, std::tuple<> >(std::_Rb_tree_const_iterator<std::pair<std::__cxx11::\
    basic_string<char, std::char_traits<char>, std::allocator<char> > const, \
    OptionSet<OptionsAsm>::Option> >, std::piecewise_construct_t const&, \
    std::tuple<std::__cxx11::basic_string<char, std::char_traits<char>, \
    std::allocator<char> >&&>&&, std::tuple<>&&) [clone .isra.74]"
    Assert.Correct(mangled, result, ItaniumDemangler())

  [<TestMethod>]
  member _.``ItaniumDemangler: Arrays``() =
    let mangled = "_ZSt9__find_ifIN9__gnu_cxx17__normal_iteratorIPNSt7__\
    cxx1112basic_stringIcSt11char_traitsIcESaIcEEESt6vectorIS7_SaIS7_EEEENS0_\
    5__ops16_Iter_equals_valIA2_KcEEET_SI_SI_T0_St26random_access_iterator_tag"
    let result = "__gnu_cxx::__normal_iterator<std::__cxx11::basic_string\
    <char, std::char_traits<char>, std::allocator<char> >*, std::vector\
    <std::__cxx11::basic_string<char, std::char_traits<char>, std::allocator\
    <char> >, std::allocator<std::__cxx11::basic_string<char, std::char_traits\
    <char>, std::allocator<char> > > > > std::__find_if<__gnu_cxx::__normal_\
    iterator<std::__cxx11::basic_string<char, std::char_traits<char>, \
    std::allocator<char> >*, std::vector<std::__cxx11::basic_string<char, \
    std::char_traits<char>, std::allocator<char> >, std::allocator<std::\
    __cxx11::basic_string<char, std::char_traits<char>, std::allocator<char> \
    > > > >, __gnu_cxx::__ops::_Iter_equals_val<char const [2]> >(__gnu_cxx::\
    __normal_iterator<std::__cxx11::basic_string<char, std::char_traits<char>, \
    std::allocator<char> >*, std::vector<std::__cxx11::basic_string<char, \
    std::char_traits<char>, std::allocator<char> >, std::allocator<std::__\
    cxx11::basic_string<char, std::char_traits<char>, std::allocator<char> > \
    > > >, __gnu_cxx::__normal_iterator<std::__cxx11::basic_string<char, \
    std::char_traits<char>, std::allocator<char> >*, std::vector<std::__cxx11\
    ::basic_string<char, std::char_traits<char>, std::allocator<char> >, \
    std::allocator<std::__cxx11::basic_string<char, std::char_traits<char>, \
    std::allocator<char> > > > >, __gnu_cxx::__ops::_Iter_equals_val<char \
    const [2]>, std::random_access_iterator_tag)"
    Assert.Correct(mangled, result, ItaniumDemangler())

  [<TestMethod>]
  member _.``ItaniumDemangler: Testing for Void 1``() =
    let mangled = "_ZN9wxPrivate11OnScopeExitI20wxObjScopeGuardImpl0I20wxWrapp\
    erInputStreamMS2_KFvvEEEEvRT_"
    let result = "void wxPrivate::OnScopeExit<wxObjScopeGuardImpl0<wxWrapper\
    InputStream, void (wxWrapperInputStream::*)() const> >(wxObjScopeGuardImp\
    l0<wxWrapperInputStream, void (wxWrapperInputStream::*)() const>&)"
    Assert.Correct(mangled, result, ItaniumDemangler())

  [<TestMethod>]
  member _.``ItaniumDemangler: Testing for Void 2``() =
    let mangled = "_ZN9wxPrivate11OnScopeExitI17wxScopeGuardImpl0IPFvvEEEEvRT_"
    let result = "void wxPrivate::OnScopeExit<wxScopeGuardImpl0<void (*)()> >\
    (wxScopeGuardImpl0<void (*)()>&)"
    Assert.Correct(mangled, result, ItaniumDemangler())
