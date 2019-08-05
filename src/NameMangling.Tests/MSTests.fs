(*
  B2R2 - the Next-Generation Reversing Platform

  Author: Michael Tegegn <mick@kaist.ac.kr>
          Sang Kil Cha <sangkilc@kaist.ac.kr>

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
type MSTests () =
  [<TestMethod>]
  member __.``MSDemangler: Nesting Test with simple names and types``() =
    let mangled = "?dog@animal@life@@YAGHF_N@Z"
    let result = "unsigned short __cdecl life::animal::dog(int,short,bool)"
    test mangled result

  [<TestMethod>]
  member __.``MSDemangler: Pointer test``() =
    let mangled = "?something@@YAXHPAPAPAPAPAG@Z"
    let result = "void __cdecl something(int,unsigned short * * * * *)"
    test mangled result

  [<TestMethod>]
  member __.``MSDemangler: Simple template argument test``() =
    let mangled = "?xyz@?$abc@HPAX@@YAXXZ"
    let result = "void __cdecl abc<int,void *>::xyz(void)"
    test mangled result

  [<TestMethod>]
  member __.``MSDemangler: Nested Templates as type and as parent class``() =
    let mangled = "?xyz@?$abc@V?$something@H@@PAX@@YAXXZ"
    let result = "void __cdecl abc<class something<int>,void *>::xyz(void)"
    test mangled result

  [<TestMethod>]
  member __.``MSDemangler: A pointer to a complex Type mangled``() =
    let mangled = "??$abc@PAV?$def@H@@PAX@@"
    let result = "abc<class def<int> *,void *>"
    test mangled result

  [<TestMethod>]
  member __.``MSDemangler: A pointer to a complex type as parent class``() =
    let mangled = "?Something@?$abc@PAU?$def@H@@PAX@@YADHG@Z"
    let result = "char __cdecl abc<struct def<int> *,void *>\
    ::Something(int,unsigned short)"
    test mangled result

  [<TestMethod>]
  member __.``MSDemangler: A pointer to a function ``() =
    let mangled = "?something@@YAHP6ADD@Z@Z"
    let result = "int __cdecl something(char (__cdecl*)(char))"
    test mangled result

  [<TestMethod>]
  member __.``MSDemangler: A double pointer to a function``() =
    let mangled = "?something@@YAHPAP6ADD@Z@Z"
    let result = "int __cdecl something(char (__cdecl* *)(char))"
    test mangled result

  [<TestMethod>]
  member __.``MSDemangler: A nested complex type and template function``() =
    let mangled = "?something@?$abc@DV?$another@U?$def@H@@@@PAH@@YAHG@Z"
    let result = "int __cdecl abc<char,class another<struct def<int>>,int *>\
    ::something(unsigned short)"
    test mangled result

  [<TestMethod>]
  member __.``MSDemangler: A special name function``() =
    let mangled = "??_G@QAFXD@Z"
    let result = "public: void __thiscall `scalar deleting destructor'(char)"
    test mangled result

  [<TestMethod>]
  member __.``MSDemangler: An RTTI code function ``() =
    let mangled = "??_R13AFD@37something@@QAGF@Z"
    let result = "public: short __stdcall something\
    ::'RTTI Base Class Descriptor at (4,83,4,8)'()"
    test mangled result

  [<TestMethod>]
  member __.``MSDemangler: A nested function mangled ``() =
    let mangled = "?abc@??abc@@YAXXZ@YAH_FJ@Z"
    let result = "int __cdecl `void __cdecl abc(void)'::abc(__int16,long)"
    test mangled result

  [<TestMethod>]
  member __.``MSDemangler: Operator mangled ``() =
    let mangled = "??_PC@YAD_F@Z"
    let result = "char __cdecl 'udt returning'operator->(__int16)"
    test mangled result

  [<TestMethod>]
  member __.``MSDemangler: Enumerated type mangled ``() =
    let mangled = "?something@@YAW7?$this@HG@nest@@HG@Z"
    let result = "enum unsigned long nest::this<int,unsigned short> \
    __cdecl something(int,unsigned short)"
    test mangled result

  [<TestMethod>]
  member __.``MSDemangler: Pointer to pointer mangled ``() =
    let mangled = "?something@@YAGQBQBPBPBPCG@Z"
    let result = "unsigned short __cdecl something\
    (unsigned short volatile * const * const * const * const * const)"
    test mangled result

  [<TestMethod>]
  member __.``MSDemangler: Pointer and class mangled``() =
    let mangled = "?something@@YAGPAQAQAQAPAGHVthisClass@@@Z"
    let result = "unsigned short __cdecl something\
    (unsigned short * * * * *,int,class thisClass)"
    test mangled result

  [<TestMethod>]
  member __.``MSDemangler: Different type of pointer mangled with modifiers ``() =
    let mangled = "?something@@YAHQFIFFKF@Z"
    let result = "int __cdecl something\
    (short volatile __unaligned __unaligned __unaligned * __restrict const)"
    test mangled result

  [<TestMethod>]
  member __.``MSDemangler: Simple name back referencing mangled ``() =
    let mangled = "?something@nested@0@YAGFD@Z"
    let result = "unsigned short __cdecl something::\
    nested::something(short,char)"
    test mangled result

  [<TestMethod>]
  member __.`` MSDemangler: Deconstructor and number namespace mangled ``() =
    let mangled = "??1?$someting@GFG@?1somethingOther@@YADFG@Z"
    let result = "char __cdecl somethingOther::`2'::someting<unsigned short\
    ,short,unsigned short>::~someting<unsigned short,short,unsigned short>\
    (short,unsigned short)"
    test mangled result

  [<TestMethod>]
  member __.`` MSDemangler: Function return type modifier mangled ``() =
    let mangled = "?something@@YA?EFFEEICDJK@Z"
    let result = "char volatile __unaligned __unaligned __ptr64 \
    __ptr64 __ptr64 __restrict __cdecl something(long,unsigned long)"
    test mangled result

  [<TestMethod>]
  member __.`` MSDemangler: Rvalue Reference mangled to a complex type ``() =
    let mangled = "?abc@@YAD$$QEFAV?$soemthing@D@@@Z"
    let result = "char __cdecl abc(class soemthing<char> \
    __unaligned && __ptr64)"
    test mangled result

  [<TestMethod>]
  member __.`` MSDemangler: Tuple as a template arguement``() =
    let mangled = "??$abc@$G5ABC@HGD@@other@@YADGH@Z"
    let result = "char __cdecl other::abc<{6,18,1891}>(unsigned short,int)"
    test mangled result

  [<TestMethod>]
  member __.`` MSDemangler: Mangled String as a templateArguement``() =
    let mangled = "??$abc@$1?somethign@@YADF@Z@other@@YADGH@Z"
    let result = "char __cdecl other::abc<&char __cdecl \
    somethign(short) >(unsigned short,int)"
    test mangled result

  [<TestMethod>]
  member __.`` MSDemangler: Constructor check``() =
    let mangled = "??0?$abc@_J@something@@YADFG@Z"
    let result = "char __cdecl something::abc<__int64>::\
    abc<__int64>(short,unsigned short)"
    test mangled result

  [<TestMethod>]
  member __.`` MSDemangler: Name Back Referencing update check``() =
    let mangled = "??6?$basic_ostream@DU?$char_traits@D@std@@@std\
    @@QAEAAV01@P6AAAV01@AAV01@@Z@Z"
    let result = "public: class std::basic_ostream<char,struct std::\
    char_traits<char>> & __thiscall std::basic_ostream<char,struct std::\
    char_traits<char>>::operator<<(class std::basic_ostream<char,struct std\
    ::char_traits<char>> & (__cdecl*)(class std::basic_ostream<char,struct \
    std::char_traits<char>> &))"
    test mangled result

  [<TestMethod>]
  member __.``MSDemangler: Constructor in template and substitutions``() =
    let mangled = "??$?0U?$default_delete@V_Facet_base@std@@@std@@$0A@@?$unique_\
    ptr@V_Facet_base@std@@U?$default_delete@V_Facet_base@std@@@2@@std@@QAE@\
    PAV_Facet_base@1@@Z"
    let result = "public: __thiscall std::unique_ptr<class std::_Facet_base,\
    struct std::default_delete<class std::_Facet_base>>::unique_ptr<class std\
    ::_Facet_base,struct std::default_delete<class std::_Facet_base>><struct \
    std::default_delete<class std::_Facet_base>,0>(class std::_Facet_base *)"
    test mangled result

  [<TestMethod>]
  member __.`` MSDemangler: nested nameOnly inside a value(not a function)``() =
    let mangled = "?_OptionsStorage@?1??__local_stdio_printf_options@@9@4_KA"
    let result = "unsigned __int64 `__local_stdio_printf_options'::`2'\
    ::_OptionsStorage"
    test mangled result

  [<TestMethod>]
  member __.`` MSDemangler: Type Back Ref check``() =
    let mangled = "?something@@YADV?$defType@D@std@@PAF0@Z"
    let result = "char __cdecl something(class std::defType<char>,short *,\
    class std::defType<char>)"
    test mangled result

  [<TestMethod>]
  member __.`` MSDemangler: Variable modifier check (not function) ``() =
    let mangled = "??_R4_Facet_base@std@@6B@"
    let result = "const std::_Facet_base::'RTTI Complete Object Locator'"
    test mangled result

  [<TestMethod>]
  member __.`` MSDemangler: Function pointer as a return Type check``() =
    let mangled = "?thisTest4@@YAPBPAP6ADD@Z@Z"
    let result = "char (__cdecl* * const * __cdecl thisTest4())(char)"
    test mangled result

  [<TestMethod>]
  member __.`` MSDemangler: Function pointer returning function check``() =
    let mangled = "?thisTest4@@YADPBPAP6AP7EF_KDD@Z@Z@Z"
    let result = "char __cdecl thisTest4(short (__thiscall*(__cdecl* * const *)\
    ())(unsigned __int64,char,char))"
    test mangled result

  [<TestMethod>]
  member __.`` MSDemangler: Array Type check``() =
    let mangled = "?something@@YAD_OEEEB_OB_OAH@Z"
    let result = "char __cdecl something(int const __ptr64 __ptr64 __ptr64[]\
    [][])"
    test mangled result

  [<TestMethod>]
  member __.`` MSDemangler: Pointer to an Array type check``() =
    let mangled = "?swapcol@@YAXPAY2DC@HHHH@HHH@D@Z"
    let result = "void __cdecl swapcol(char (*)[50][30583][1911])"
    test mangled result

  [<TestMethod>]
  member __.`` MSDemangler: Ignored __based cvModifier``() =
    let mangled = "?something@@YADPM5G@Z"
    let result = "char __cdecl something(unsigned short)"
    test mangled result

  [<TestMethod>]
  member __.`` MSDemangler: __based cvModified pointer to name ``() =
    let mangled = "?something@@YADPM2something@nested@@G@Z"
    let result = "char __cdecl something(unsigned short __based(nested::\
    something)*)"
    test mangled result

  [<TestMethod>]
  member __.`` MSDemangler: cvModified pointer to a member ``() =
    let mangled = "?something@@YADFQQfunc@parent@@_K@Z"
    let result = "char __cdecl something(short,unsigned __int64 parent::\
    func::* const)"
    test mangled result

  [<TestMethod>]
  member __.`` MSDemangler: Function pointer with ignored pointer types  ``() =
    let mangled = "?something@@QEADPAQEEEAPAQ6CDH@Z@Z"
    let result = "public: char (__pascal* * * __ptr64 __ptr64 __ptr64 * \
    __pascal something()  __ptr64)(int)"
    test mangled result

  [<TestMethod>]
  member __.`` MSDemangler: Substitution check for extended types  ``() =
    let mangled = "?func@@YAX$$T_NPDSAP6AHH0@ZP6AH0@ZV?$someother@_NF@std@@1@Z"
    let result = "void __cdecl func(std::nullptr_t,bool,int (__cdecl* * const \
    volatile *)(int,std::nullptr_t),int (__cdecl*)(std::nullptr_t),class std::\
    someother<bool,short>,bool)"
    test mangled result

  [<TestMethod>]
  member __.`` MSDemangler: Return type operator updated``() =
    let mangled = "??Bstd@netbase@@YADF@Z"
    let result = "__cdecl netbase::std::operator char(short)"
    test mangled result

  [<TestMethod>]
  member __.`` MSDemangler: Mangled string constant``() =
    let mangled = "??_C@_0O@EMEFIAMJ@?6Enter?5data?3?5@"
    let result = "`string'"
    test mangled result

  [<TestMethod>]
  member __.`` MSDemangler: Different access level data test``() =
    let mangled = "?_Psave@?$_Facetptr@V?$ctype@D@std@@@std\
    @@2PBVfacet@locale@1@B"
    let result = "public: static class _Facetptr<class std::ctype<char>>::\
    locale::facet const * const std::_Facetptr<class std::ctype<char>>::_Psave"
    test mangled result

  [<TestMethod>]
  member __.`` MSDemangler: Dynamic special Name bug test``() =
    let mangled = "??__E?ms_classInfo@wxAuiToolBar@@2VwxClassInfo@@A@@YAXXZ"
    let result = "void __cdecl `dynamic initializer for 'public: static class \
    wxClassInfo wxAuiToolBar::ms_classInfo''(void)"
    test mangled result

  [<TestMethod>]
  member __.`` MSDemangler: Dynamic special Name bug test 2``() =
    let mangled = "??__EwxEVT_AUITOOLBAR_TOOL_DROPDOWN@@YAXXZ"
    let result = "void __cdecl `dynamic initializer for 'wxEVT_AUITOOLBAR_TOOL\
    _DROPDOWN''(void)"
    test mangled result

  [<TestMethod>]
  member __.`` MSDemangler: Member function pointer bug test``() =
    let mangled = "?GetEvtMethod@?$wxEventFunctorMethod@V?$wxEventTypeTag@VwxSi\
    zeEvent@@@@VwxEvtHandler@@VwxEvent@@V2@@@UBEP8wxEvtHandler@@AEXAAVwxEvent@\
    @@ZXZ"
    let result = "public: virtual void (__thiscall wxEvtHandler::* __thiscall w\
    xEventFunctorMethod<class wxEventTypeTag<class wxSizeEvent>,class wxEvtHand\
    ler,class wxEvent,class wxEvtHandler>::GetEvtMethod(void) const)(class wxEv\
    ent &)"
    test mangled result

  [<TestMethod>]
  member __.`` MSDemangler: Thunk Function check``() =
    let mangled = "??_EwxSizer@@X7BAPAXI@Z"
    let result = "[thunk]:public: virtual void * __cdecl wxSizer::`vector \
    deleting destructor'`adjustor{8}'(unsigned int) const"
    test mangled result

  [<TestMethod>]
  member __.`` MSDemangler: Anonymous namespace check``() =
    let mangled = "?MergeLayout@wxAuiLayoutObject@?A0x7605e013@@QAEXABV12@@Z"
    let result = "public: void __thiscall `anonymous namespace'::wxAuiLayoutOb\
    ject::MergeLayout(class A0x7605e013::wxAuiLayoutObject const &)"
    test mangled result

  [<TestMethod>]
  member __.`` MSDemangler: Function pointer substitution bug test``() =
    let mangled = "??$OnScopeExit@V?$wxScopeGuardImpl3@P6AXPAPAVwxAuiToolBarI\
    tem@@0I@ZPAPAV1@PAPAV1@I@@@wxPrivate@@YAXAAV?$wxScopeGuardImpl3@P6AXPAPAVwx\
    AuiToolBarItem@@0I@ZPAPAV1@PAPAV1@I@@@Z"
    let result = "void __cdecl wxPrivate::OnScopeExit<class wxScopeGuardImpl3\
    <void (__cdecl*)(class wxAuiToolBarItem * *,class wxAuiToolBarItem * *,uns\
    igned int),class wxAuiToolBarItem * *,class wxAuiToolBarItem * *,unsigned \
    int>>(class wxScopeGuardImpl3<void (__cdecl*)(class wxAuiToolBarItem * *,\
    class wxAuiToolBarItem * *,unsigned int),class wxAuiToolBarItem * *,class \
    wxAuiToolBarItem * *,unsigned int> &)"
    test mangled result

  [<TestMethod>]
  member __.`` MSDemangler: Dynamic special name on value bug check``() =
    let mangled = "??__F?sm_eventTableEntries@wxAuiToolBar@@0QBUwxEventTableEn\
    try@@B@@YAXXZ"
    let result = "void __cdecl `dynamic atexit destructor for 'private: static \
    struct wxEventTableEntry const * const wxAuiToolBar::sm_eventTableEntries''\
    (void)"
    test mangled result

  [<TestMethod>]
  member __.`` MSDemangler: Incomplete function parameter pack check``() =
    let mangled = "?DoPrintfWchar@wxString@@AAAHPB_WZZ"
    let result = "private: int __cdecl wxString::DoPrintfWchar(wchar_t const \
    *,...)"
    test mangled result