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

namespace B2R2.FrontEnd.BinLifter.RISCV

open B2R2
open B2R2.FrontEnd
open B2R2.FrontEnd.Register
open B2R2.FrontEnd.BinLifter.LiftingUtils
open B2R2.BinIR.LowUIR
open B2R2.BinIR.LowUIR.AST.InfixOp

type RegExprs (wordSize) =
  let var sz t name = AST.var sz t name

  (* RISCV64. *)
  let regType = WordSize.toRegType wordSize
  let fflags = var 32<rt> (RISCV64Register.ID RISCV64.FFLAGS) "FFLAGS"
  let frm = var 32<rt> (RISCV64Register.ID RISCV64.FRM) "FRM"

  member val X0 = var regType (RISCV64Register.ID RISCV64.X0) "X0" with get
  member val X1 = var regType (RISCV64Register.ID RISCV64.X1) "X1" with get
  member val X2 = var regType (RISCV64Register.ID RISCV64.X2) "X2" with get
  member val X3 = var regType (RISCV64Register.ID RISCV64.X3) "X3" with get
  member val X4 = var regType (RISCV64Register.ID RISCV64.X4) "X4" with get
  member val X5 = var regType (RISCV64Register.ID RISCV64.X5) "X5" with get
  member val X6 = var regType (RISCV64Register.ID RISCV64.X6) "X6" with get
  member val X7 = var regType (RISCV64Register.ID RISCV64.X7) "X7" with get
  member val X8 = var regType (RISCV64Register.ID RISCV64.X8) "X8" with get
  member val X9 = var regType (RISCV64Register.ID RISCV64.X9) "X9" with get
  member val X10 = var regType (RISCV64Register.ID RISCV64.X10) "X10" with get
  member val X11 = var regType (RISCV64Register.ID RISCV64.X11) "X11" with get
  member val X12 = var regType (RISCV64Register.ID RISCV64.X12) "X12" with get
  member val X13 = var regType (RISCV64Register.ID RISCV64.X13) "X13" with get
  member val X14 = var regType (RISCV64Register.ID RISCV64.X14) "X14" with get
  member val X15 = var regType (RISCV64Register.ID RISCV64.X15) "X15" with get
  member val X16 = var regType (RISCV64Register.ID RISCV64.X16) "X16" with get
  member val X17 = var regType (RISCV64Register.ID RISCV64.X17) "X17" with get
  member val X18 = var regType (RISCV64Register.ID RISCV64.X18) "X18" with get
  member val X19 = var regType (RISCV64Register.ID RISCV64.X19) "X19" with get
  member val X20 = var regType (RISCV64Register.ID RISCV64.X20) "X20" with get
  member val X21 = var regType (RISCV64Register.ID RISCV64.X21) "X21" with get
  member val X22 = var regType (RISCV64Register.ID RISCV64.X22) "X22" with get
  member val X23 = var regType (RISCV64Register.ID RISCV64.X23) "X23" with get
  member val X24 = var regType (RISCV64Register.ID RISCV64.X24) "X24" with get
  member val X25 = var regType (RISCV64Register.ID RISCV64.X25) "X25" with get
  member val X26 = var regType (RISCV64Register.ID RISCV64.X26) "X26" with get
  member val X27 = var regType (RISCV64Register.ID RISCV64.X27) "X27" with get
  member val X28 = var regType (RISCV64Register.ID RISCV64.X28) "X28" with get
  member val X29 = var regType (RISCV64Register.ID RISCV64.X29) "X29" with get
  member val X30 = var regType (RISCV64Register.ID RISCV64.X30) "X30" with get
  member val X31 = var regType (RISCV64Register.ID RISCV64.X31) "X31" with get

  member val F0 = var regType (RISCV64Register.ID RISCV64.F0) "F0" with get
  member val F1 = var regType (RISCV64Register.ID RISCV64.F1) "F1" with get
  member val F2 = var regType (RISCV64Register.ID RISCV64.F2) "F2" with get
  member val F3 = var regType (RISCV64Register.ID RISCV64.F3) "F3" with get
  member val F4 = var regType (RISCV64Register.ID RISCV64.F4) "F4" with get
  member val F5 = var regType (RISCV64Register.ID RISCV64.F5) "F5" with get
  member val F6 = var regType (RISCV64Register.ID RISCV64.F6) "F6" with get
  member val F7 = var regType (RISCV64Register.ID RISCV64.F7) "F7" with get
  member val F8 = var regType (RISCV64Register.ID RISCV64.F8) "F8" with get
  member val F9 = var regType (RISCV64Register.ID RISCV64.F9) "F9" with get
  member val F10 = var regType (RISCV64Register.ID RISCV64.F10) "F10" with get
  member val F11 = var regType (RISCV64Register.ID RISCV64.F11) "F11" with get
  member val F12 = var regType (RISCV64Register.ID RISCV64.F12) "F12" with get
  member val F13 = var regType (RISCV64Register.ID RISCV64.F13) "F13" with get
  member val F14 = var regType (RISCV64Register.ID RISCV64.F14) "F14" with get
  member val F15 = var regType (RISCV64Register.ID RISCV64.F15) "F15" with get
  member val F16 = var regType (RISCV64Register.ID RISCV64.F16) "F16" with get
  member val F17 = var regType (RISCV64Register.ID RISCV64.F17) "F17" with get
  member val F18 = var regType (RISCV64Register.ID RISCV64.F18) "F18" with get
  member val F19 = var regType (RISCV64Register.ID RISCV64.F19) "F19" with get
  member val F20 = var regType (RISCV64Register.ID RISCV64.F20) "F20" with get
  member val F21 = var regType (RISCV64Register.ID RISCV64.F21) "F21" with get
  member val F22 = var regType (RISCV64Register.ID RISCV64.F22) "F22" with get
  member val F23 = var regType (RISCV64Register.ID RISCV64.F23) "F23" with get
  member val F24 = var regType (RISCV64Register.ID RISCV64.F24) "F24" with get
  member val F25 = var regType (RISCV64Register.ID RISCV64.F25) "F25" with get
  member val F26 = var regType (RISCV64Register.ID RISCV64.F26) "F26" with get
  member val F27 = var regType (RISCV64Register.ID RISCV64.F27) "F27" with get
  member val F28 = var regType (RISCV64Register.ID RISCV64.F28) "F28" with get
  member val F29 = var regType (RISCV64Register.ID RISCV64.F29) "F29" with get
  member val F30 = var regType (RISCV64Register.ID RISCV64.F30) "F30" with get
  member val F31 = var regType (RISCV64Register.ID RISCV64.F31) "F31" with get

  member val PC = AST.pcvar regType "PC" with get
  member val RC = var 1<rt> (RISCV64Register.ID RISCV64.RC) "RC" with get
  member val FFLAGS = fflags with get
  member val FRM = frm with get
  member val FCSR =
    (fflags .& (numI32 0b11111 32<rt>))
    .| ((frm .& (numI32 0b111 32<rt>)) << numI32 5 32<rt>) with get

  member val CSR0768 =
    var regType (RISCV64Register.ID RISCV64.CSR0768) "CSR0768" with get
  member val CSR0769 =
    var regType (RISCV64Register.ID RISCV64.CSR0769) "CSR0769" with get
  member val CSR0770 =
    var regType (RISCV64Register.ID RISCV64.CSR0770) "CSR0770" with get
  member val CSR0771 =
    var regType (RISCV64Register.ID RISCV64.CSR0771) "CSR0771" with get
  member val CSR0772 =
    var regType (RISCV64Register.ID RISCV64.CSR0772) "CSR0772" with get
  member val CSR0773 =
    var regType (RISCV64Register.ID RISCV64.CSR0773) "CSR0773" with get
  member val CSR0784 =
    var regType (RISCV64Register.ID RISCV64.CSR0784) "CSR0784" with get
  member val CSR0832 =
    var regType (RISCV64Register.ID RISCV64.CSR0832) "CSR0832" with get
  member val CSR0833 =
    var regType (RISCV64Register.ID RISCV64.CSR0833) "CSR0833" with get
  member val CSR0834 =
    var regType (RISCV64Register.ID RISCV64.CSR0834) "CSR0834" with get
  member val CSR0835 =
    var regType (RISCV64Register.ID RISCV64.CSR0835) "CSR0835" with get
  member val CSR0836 =
    var regType (RISCV64Register.ID RISCV64.CSR0836) "CSR0836" with get
  member val CSR0842 =
    var regType (RISCV64Register.ID RISCV64.CSR0842) "CSR0842" with get
  member val CSR0843 =
    var regType (RISCV64Register.ID RISCV64.CSR0843) "CSR0843" with get
  member val CSR3114 =
    var regType (RISCV64Register.ID RISCV64.CSR3114) "CSR3114" with get
  member val CSR3787 =
    var regType (RISCV64Register.ID RISCV64.CSR3787) "CSR3787" with get
  member val CSR3857 =
    var regType (RISCV64Register.ID RISCV64.CSR3857) "CSR3857" with get
  member val CSR3858 =
    var regType (RISCV64Register.ID RISCV64.CSR3858) "CSR3858" with get
  member val CSR3859 =
    var regType (RISCV64Register.ID RISCV64.CSR3859) "CSR3859" with get
  member val CSR3860 =
    var regType (RISCV64Register.ID RISCV64.CSR3860) "CSR3860" with get
  member val CSR0928 =
    var regType (RISCV64Register.ID RISCV64.CSR0928) "CSR0928" with get
  member val CSR0930 =
    var regType (RISCV64Register.ID RISCV64.CSR0930) "CSR0930" with get
  member val CSR0932 =
    var regType (RISCV64Register.ID RISCV64.CSR0932) "CSR0932" with get
  member val CSR0934 =
    var regType (RISCV64Register.ID RISCV64.CSR0934) "CSR0934" with get
  member val CSR0936 =
    var regType (RISCV64Register.ID RISCV64.CSR0936) "CSR0936" with get
  member val CSR0938 =
    var regType (RISCV64Register.ID RISCV64.CSR0938) "CSR0938" with get
  member val CSR0940 =
    var regType (RISCV64Register.ID RISCV64.CSR0940) "CSR0940" with get
  member val CSR0942 =
    var regType (RISCV64Register.ID RISCV64.CSR0942) "CSR0942" with get
  member val CSR0944 =
    var regType (RISCV64Register.ID RISCV64.CSR0944) "CSR0944" with get
  member val CSR0945 =
    var regType (RISCV64Register.ID RISCV64.CSR0945) "CSR0945" with get
  member val CSR0946 =
    var regType (RISCV64Register.ID RISCV64.CSR0946) "CSR0946" with get
  member val CSR0947 =
    var regType (RISCV64Register.ID RISCV64.CSR0947) "CSR0947" with get
  member val CSR0948 =
    var regType (RISCV64Register.ID RISCV64.CSR0948) "CSR0948" with get
  member val CSR0949 =
    var regType (RISCV64Register.ID RISCV64.CSR0949) "CSR0949" with get
  member val CSR0950 =
    var regType (RISCV64Register.ID RISCV64.CSR0950) "CSR0950" with get
  member val CSR0951 =
    var regType (RISCV64Register.ID RISCV64.CSR0951) "CSR0951" with get
  member val CSR0952 =
    var regType (RISCV64Register.ID RISCV64.CSR0952) "CSR0952" with get
  member val CSR0953 =
    var regType (RISCV64Register.ID RISCV64.CSR0953) "CSR0953" with get
  member val CSR0954 =
    var regType (RISCV64Register.ID RISCV64.CSR0954) "CSR0954" with get
  member val CSR0955 =
    var regType (RISCV64Register.ID RISCV64.CSR0955) "CSR0955" with get
  member val CSR0956 =
    var regType (RISCV64Register.ID RISCV64.CSR0956) "CSR0956" with get
  member val CSR0957 =
    var regType (RISCV64Register.ID RISCV64.CSR0957) "CSR0957" with get
  member val CSR0958 =
    var regType (RISCV64Register.ID RISCV64.CSR0958) "CSR0958" with get
  member val CSR0959 =
    var regType (RISCV64Register.ID RISCV64.CSR0959) "CSR0959" with get
  member val CSR0960 =
    var regType (RISCV64Register.ID RISCV64.CSR0960) "CSR0960" with get
  member val CSR0961 =
    var regType (RISCV64Register.ID RISCV64.CSR0961) "CSR0961" with get
  member val CSR0962 =
    var regType (RISCV64Register.ID RISCV64.CSR0962) "CSR0962" with get
  member val CSR0963 =
    var regType (RISCV64Register.ID RISCV64.CSR0963) "CSR0963" with get
  member val CSR0964 =
    var regType (RISCV64Register.ID RISCV64.CSR0964) "CSR0964" with get
  member val CSR0965 =
    var regType (RISCV64Register.ID RISCV64.CSR0965) "CSR0965" with get
  member val CSR0966 =
    var regType (RISCV64Register.ID RISCV64.CSR0966) "CSR0966" with get
  member val CSR0967 =
    var regType (RISCV64Register.ID RISCV64.CSR0967) "CSR0967" with get
  member val CSR0968 =
    var regType (RISCV64Register.ID RISCV64.CSR0968) "CSR0968" with get
  member val CSR0969 =
    var regType (RISCV64Register.ID RISCV64.CSR0969) "CSR0969" with get
  member val CSR0970 =
    var regType (RISCV64Register.ID RISCV64.CSR0970) "CSR0970" with get
  member val CSR0971 =
    var regType (RISCV64Register.ID RISCV64.CSR0971) "CSR0971" with get
  member val CSR0972 =
    var regType (RISCV64Register.ID RISCV64.CSR0972) "CSR0972" with get
  member val CSR0973 =
    var regType (RISCV64Register.ID RISCV64.CSR0973) "CSR0973" with get
  member val CSR0974 =
    var regType (RISCV64Register.ID RISCV64.CSR0974) "CSR0974" with get
  member val CSR0975 =
    var regType (RISCV64Register.ID RISCV64.CSR0975) "CSR0975" with get
  member val CSR0976 =
    var regType (RISCV64Register.ID RISCV64.CSR0976) "CSR0976" with get
  member val CSR0977 =
    var regType (RISCV64Register.ID RISCV64.CSR0977) "CSR0977" with get
  member val CSR0978 =
    var regType (RISCV64Register.ID RISCV64.CSR0978) "CSR0978" with get
  member val CSR0979 =
    var regType (RISCV64Register.ID RISCV64.CSR0979) "CSR0979" with get
  member val CSR0980 =
    var regType (RISCV64Register.ID RISCV64.CSR0980) "CSR0980" with get
  member val CSR0981 =
    var regType (RISCV64Register.ID RISCV64.CSR0981) "CSR0981" with get
  member val CSR0982 =
    var regType (RISCV64Register.ID RISCV64.CSR0982) "CSR0982" with get
  member val CSR0983 =
    var regType (RISCV64Register.ID RISCV64.CSR0983) "CSR0983" with get
  member val CSR0984 =
    var regType (RISCV64Register.ID RISCV64.CSR0984) "CSR0984" with get
  member val CSR0985 =
    var regType (RISCV64Register.ID RISCV64.CSR0985) "CSR0985" with get
  member val CSR0986 =
    var regType (RISCV64Register.ID RISCV64.CSR0986) "CSR0986" with get
  member val CSR0987 =
    var regType (RISCV64Register.ID RISCV64.CSR0987) "CSR0987" with get
  member val CSR0988 =
    var regType (RISCV64Register.ID RISCV64.CSR0988) "CSR0988" with get
  member val CSR0989 =
    var regType (RISCV64Register.ID RISCV64.CSR0989) "CSR0989" with get
  member val CSR0990 =
    var regType (RISCV64Register.ID RISCV64.CSR0990) "CSR0990" with get
  member val CSR0991 =
    var regType (RISCV64Register.ID RISCV64.CSR0991) "CSR0991" with get
  member val CSR0992 =
    var regType (RISCV64Register.ID RISCV64.CSR0992) "CSR0992" with get
  member val CSR0993 =
    var regType (RISCV64Register.ID RISCV64.CSR0993) "CSR0993" with get
  member val CSR0994 =
    var regType (RISCV64Register.ID RISCV64.CSR0994) "CSR0994" with get
  member val CSR0995 =
    var regType (RISCV64Register.ID RISCV64.CSR0995) "CSR0995" with get
  member val CSR0996 =
    var regType (RISCV64Register.ID RISCV64.CSR0996) "CSR0996" with get
  member val CSR0997 =
    var regType (RISCV64Register.ID RISCV64.CSR0997) "CSR0997" with get
  member val CSR0998 =
    var regType (RISCV64Register.ID RISCV64.CSR0998) "CSR0998" with get
  member val CSR0999 =
    var regType (RISCV64Register.ID RISCV64.CSR0999) "CSR0999" with get
  member val CSR1000 =
    var regType (RISCV64Register.ID RISCV64.CSR1000) "CSR1000" with get
  member val CSR1001 =
    var regType (RISCV64Register.ID RISCV64.CSR1001) "CSR1001" with get
  member val CSR1002 =
    var regType (RISCV64Register.ID RISCV64.CSR1002) "CSR1002" with get
  member val CSR1003 =
    var regType (RISCV64Register.ID RISCV64.CSR1003) "CSR1003" with get
  member val CSR1004 =
    var regType (RISCV64Register.ID RISCV64.CSR1004) "CSR1004" with get
  member val CSR1005 =
    var regType (RISCV64Register.ID RISCV64.CSR1005) "CSR1005" with get
  member val CSR1006 =
    var regType (RISCV64Register.ID RISCV64.CSR1006) "CSR1006" with get
  member val CSR1007 =
    var regType (RISCV64Register.ID RISCV64.CSR1007) "CSR1007" with get
  member val CSR2145 =
    var regType (RISCV64Register.ID RISCV64.CSR2145) "CSR2145" with get
  member val CSR2617 =
    var regType (RISCV64Register.ID RISCV64.CSR2617) "CSR2617" with get
  member val CSR2816 =
    var regType (RISCV64Register.ID RISCV64.CSR2816) "CSR2816" with get
  member val CSR2818 =
    var regType (RISCV64Register.ID RISCV64.CSR2818) "CSR2818" with get
  member val CSR2819 =
    var regType (RISCV64Register.ID RISCV64.CSR2819) "CSR2819" with get
  member val CSR2820 =
    var regType (RISCV64Register.ID RISCV64.CSR2820) "CSR2820" with get
  member val CSR2821 =
    var regType (RISCV64Register.ID RISCV64.CSR2821) "CSR2821" with get
  member val CSR2822 =
    var regType (RISCV64Register.ID RISCV64.CSR2822) "CSR2822" with get
  member val CSR2823 =
    var regType (RISCV64Register.ID RISCV64.CSR2823) "CSR2823" with get
  member val CSR2824 =
    var regType (RISCV64Register.ID RISCV64.CSR2824) "CSR2824" with get
  member val CSR2825 =
    var regType (RISCV64Register.ID RISCV64.CSR2825) "CSR2825" with get
  member val CSR2826 =
    var regType (RISCV64Register.ID RISCV64.CSR2826) "CSR2826" with get
  member val CSR2827 =
    var regType (RISCV64Register.ID RISCV64.CSR2827) "CSR2827" with get
  member val CSR2828 =
    var regType (RISCV64Register.ID RISCV64.CSR2828) "CSR2828" with get
  member val CSR2829 =
    var regType (RISCV64Register.ID RISCV64.CSR2829) "CSR2829" with get
  member val CSR2830 =
    var regType (RISCV64Register.ID RISCV64.CSR2830) "CSR2830" with get
  member val CSR2831 =
    var regType (RISCV64Register.ID RISCV64.CSR2831) "CSR2831" with get
  member val CSR2832 =
    var regType (RISCV64Register.ID RISCV64.CSR2832) "CSR2832" with get
  member val CSR2833 =
    var regType (RISCV64Register.ID RISCV64.CSR2833) "CSR2833" with get
  member val CSR2834 =
    var regType (RISCV64Register.ID RISCV64.CSR2834) "CSR2834" with get
  member val CSR2835 =
    var regType (RISCV64Register.ID RISCV64.CSR2835) "CSR2835" with get
  member val CSR2836 =
    var regType (RISCV64Register.ID RISCV64.CSR2836) "CSR2836" with get
  member val CSR2837 =
    var regType (RISCV64Register.ID RISCV64.CSR2837) "CSR2837" with get
  member val CSR2838 =
    var regType (RISCV64Register.ID RISCV64.CSR2838) "CSR2838" with get
  member val CSR2839 =
    var regType (RISCV64Register.ID RISCV64.CSR2839) "CSR2839" with get
  member val CSR2840 =
    var regType (RISCV64Register.ID RISCV64.CSR2840) "CSR2840" with get
  member val CSR2841 =
    var regType (RISCV64Register.ID RISCV64.CSR2841) "CSR2841" with get
  member val CSR2842 =
    var regType (RISCV64Register.ID RISCV64.CSR2842) "CSR2842" with get
  member val CSR2843 =
    var regType (RISCV64Register.ID RISCV64.CSR2843) "CSR2843" with get
  member val CSR2844 =
    var regType (RISCV64Register.ID RISCV64.CSR2844) "CSR2844" with get
  member val CSR2845 =
    var regType (RISCV64Register.ID RISCV64.CSR2845) "CSR2845" with get
  member val CSR2846 =
    var regType (RISCV64Register.ID RISCV64.CSR2846) "CSR2846" with get
  member val CSR2847 =
    var regType (RISCV64Register.ID RISCV64.CSR2847) "CSR2847" with get
  member val CSR2945 =
    var regType (RISCV64Register.ID RISCV64.CSR2945) "CSR2945" with get
  member val CSR0800 =
    var regType (RISCV64Register.ID RISCV64.CSR0800) "CSR0800" with get
  member val CSR0803 =
    var regType (RISCV64Register.ID RISCV64.CSR0803) "CSR0803" with get
  member val CSR0804 =
    var regType (RISCV64Register.ID RISCV64.CSR0804) "CSR0804" with get
  member val CSR0805 =
    var regType (RISCV64Register.ID RISCV64.CSR0805) "CSR0805" with get
  member val CSR0806 =
    var regType (RISCV64Register.ID RISCV64.CSR0806) "CSR0806" with get
  member val CSR0807 =
    var regType (RISCV64Register.ID RISCV64.CSR0807) "CSR0807" with get
  member val CSR0808 =
    var regType (RISCV64Register.ID RISCV64.CSR0808) "CSR0808" with get
  member val CSR0809 =
    var regType (RISCV64Register.ID RISCV64.CSR0809) "CSR0809" with get
  member val CSR0810 =
    var regType (RISCV64Register.ID RISCV64.CSR0810) "CSR0810" with get
  member val CSR0811 =
    var regType (RISCV64Register.ID RISCV64.CSR0811) "CSR0811" with get
  member val CSR0812 =
    var regType (RISCV64Register.ID RISCV64.CSR0812) "CSR0812" with get
  member val CSR0813 =
    var regType (RISCV64Register.ID RISCV64.CSR0813) "CSR0813" with get
  member val CSR0814 =
    var regType (RISCV64Register.ID RISCV64.CSR0814) "CSR0814" with get
  member val CSR0815 =
    var regType (RISCV64Register.ID RISCV64.CSR0815) "CSR0815" with get
  member val CSR0816 =
    var regType (RISCV64Register.ID RISCV64.CSR0816) "CSR0816" with get
  member val CSR0817 =
    var regType (RISCV64Register.ID RISCV64.CSR0817) "CSR0817" with get
  member val CSR0818 =
    var regType (RISCV64Register.ID RISCV64.CSR0818) "CSR0818" with get
  member val CSR0819 =
    var regType (RISCV64Register.ID RISCV64.CSR0819) "CSR0819" with get
  member val CSR0820 =
    var regType (RISCV64Register.ID RISCV64.CSR0820) "CSR0820" with get
  member val CSR0821 =
    var regType (RISCV64Register.ID RISCV64.CSR0821) "CSR0821" with get
  member val CSR0822 =
    var regType (RISCV64Register.ID RISCV64.CSR0822) "CSR0822" with get
  member val CSR0823 =
    var regType (RISCV64Register.ID RISCV64.CSR0823) "CSR0823" with get
  member val CSR0824 =
    var regType (RISCV64Register.ID RISCV64.CSR0824) "CSR0824" with get
  member val CSR0825 =
    var regType (RISCV64Register.ID RISCV64.CSR0825) "CSR0825" with get
  member val CSR0826 =
    var regType (RISCV64Register.ID RISCV64.CSR0826) "CSR0826" with get
  member val CSR0827 =
    var regType (RISCV64Register.ID RISCV64.CSR0827) "CSR0827" with get
  member val CSR0828 =
    var regType (RISCV64Register.ID RISCV64.CSR0828) "CSR0828" with get
  member val CSR0829 =
    var regType (RISCV64Register.ID RISCV64.CSR0829) "CSR0829" with get
  member val CSR0830 =
    var regType (RISCV64Register.ID RISCV64.CSR0830) "CSR0830" with get
  member val CSR0831 =
    var regType (RISCV64Register.ID RISCV64.CSR0831) "CSR0831" with get
  member val CSR1952 =
    var regType (RISCV64Register.ID RISCV64.CSR1952) "CSR1952" with get
  member val CSR1953 =
    var regType (RISCV64Register.ID RISCV64.CSR1953) "CSR1953" with get
  member val CSR1954 =
    var regType (RISCV64Register.ID RISCV64.CSR1954) "CSR1954" with get
  member val CSR1955 =
    var regType (RISCV64Register.ID RISCV64.CSR1955) "CSR1955" with get
  member val CSR1968 =
    var regType (RISCV64Register.ID RISCV64.CSR1968) "CSR1968" with get
  member val CSR1969 =
    var regType (RISCV64Register.ID RISCV64.CSR1969) "CSR1969" with get
  member val CSR1970 =
    var regType (RISCV64Register.ID RISCV64.CSR1970) "CSR1970" with get
  member val CSR1971 =
    var regType (RISCV64Register.ID RISCV64.CSR1971) "CSR1971" with get

  member __.GetRegVar (name) =
    match name with
    | RISCV64.PC  -> __.PC
    | RISCV64.RC -> __.RC
    | RISCV64.X0 -> __.X0
    | RISCV64.X1 -> __.X1
    | RISCV64.X2 -> __.X2
    | RISCV64.X3 -> __.X3
    | RISCV64.X4 -> __.X4
    | RISCV64.X5 -> __.X5
    | RISCV64.X6 -> __.X6
    | RISCV64.X7 -> __.X7
    | RISCV64.X8 -> __.X8
    | RISCV64.X9 -> __.X9
    | RISCV64.X10 -> __.X10
    | RISCV64.X11 -> __.X11
    | RISCV64.X12 -> __.X12
    | RISCV64.X13 -> __.X13
    | RISCV64.X14 -> __.X14
    | RISCV64.X15 -> __.X15
    | RISCV64.X16 -> __.X16
    | RISCV64.X17 -> __.X17
    | RISCV64.X18 -> __.X18
    | RISCV64.X19 -> __.X19
    | RISCV64.X20 -> __.X20
    | RISCV64.X21 -> __.X21
    | RISCV64.X22 -> __.X22
    | RISCV64.X23 -> __.X23
    | RISCV64.X24 -> __.X24
    | RISCV64.X25 -> __.X25
    | RISCV64.X26 -> __.X26
    | RISCV64.X27 -> __.X27
    | RISCV64.X28 -> __.X28
    | RISCV64.X29 -> __.X29
    | RISCV64.X30 -> __.X30
    | RISCV64.X31 -> __.X31
    | RISCV64.F0 -> __.F0
    | RISCV64.F1 -> __.F1
    | RISCV64.F2 -> __.F2
    | RISCV64.F3 -> __.F3
    | RISCV64.F4 -> __.F4
    | RISCV64.F5 -> __.F5
    | RISCV64.F6 -> __.F6
    | RISCV64.F7 -> __.F7
    | RISCV64.F8 -> __.F8
    | RISCV64.F9 -> __.F9
    | RISCV64.F10 -> __.F10
    | RISCV64.F11 -> __.F11
    | RISCV64.F12 -> __.F12
    | RISCV64.F13 -> __.F13
    | RISCV64.F14 -> __.F14
    | RISCV64.F15 -> __.F15
    | RISCV64.F16 -> __.F16
    | RISCV64.F17 -> __.F17
    | RISCV64.F18 -> __.F18
    | RISCV64.F19 -> __.F19
    | RISCV64.F20 -> __.F20
    | RISCV64.F21 -> __.F21
    | RISCV64.F22 -> __.F22
    | RISCV64.F23 -> __.F23
    | RISCV64.F24 -> __.F24
    | RISCV64.F25 -> __.F25
    | RISCV64.F26 -> __.F26
    | RISCV64.F27 -> __.F27
    | RISCV64.F28 -> __.F28
    | RISCV64.F29 -> __.F29
    | RISCV64.F30 -> __.F30
    | RISCV64.F31 -> __.F31
    | RISCV64.FFLAGS -> __.FFLAGS
    | RISCV64.FRM -> __.FRM
    | RISCV64.FCSR -> __.FCSR
    | RISCV64.CSR0768 -> __.CSR0768
    | RISCV64.CSR0769 -> __.CSR0769
    | RISCV64.CSR0770 -> __.CSR0770
    | RISCV64.CSR0771 -> __.CSR0771
    | RISCV64.CSR0772 -> __.CSR0772
    | RISCV64.CSR0773 -> __.CSR0773
    | RISCV64.CSR0784 -> __.CSR0784
    | RISCV64.CSR0832 -> __.CSR0832
    | RISCV64.CSR0833 -> __.CSR0833
    | RISCV64.CSR0834 -> __.CSR0834
    | RISCV64.CSR0835 -> __.CSR0835
    | RISCV64.CSR0836 -> __.CSR0836
    | RISCV64.CSR0842 -> __.CSR0842
    | RISCV64.CSR0843 -> __.CSR0843
    | RISCV64.CSR3114 -> __.CSR3114
    | RISCV64.CSR3787 -> __.CSR3787
    | RISCV64.CSR3857 -> __.CSR3857
    | RISCV64.CSR3858 -> __.CSR3858
    | RISCV64.CSR3859 -> __.CSR3859
    | RISCV64.CSR3860 -> __.CSR3860
    | RISCV64.CSR0928 -> __.CSR0928
    | RISCV64.CSR0930 -> __.CSR0930
    | RISCV64.CSR0932 -> __.CSR0932
    | RISCV64.CSR0934 -> __.CSR0934
    | RISCV64.CSR0936 -> __.CSR0936
    | RISCV64.CSR0938 -> __.CSR0938
    | RISCV64.CSR0940 -> __.CSR0940
    | RISCV64.CSR0942 -> __.CSR0942
    | RISCV64.CSR0944 -> __.CSR0944
    | RISCV64.CSR0945 -> __.CSR0945
    | RISCV64.CSR0946 -> __.CSR0946
    | RISCV64.CSR0947 -> __.CSR0947
    | RISCV64.CSR0948 -> __.CSR0948
    | RISCV64.CSR0949 -> __.CSR0949
    | RISCV64.CSR0950 -> __.CSR0950
    | RISCV64.CSR0951 -> __.CSR0951
    | RISCV64.CSR0952 -> __.CSR0952
    | RISCV64.CSR0953 -> __.CSR0953
    | RISCV64.CSR0954 -> __.CSR0954
    | RISCV64.CSR0955 -> __.CSR0955
    | RISCV64.CSR0956 -> __.CSR0956
    | RISCV64.CSR0957 -> __.CSR0957
    | RISCV64.CSR0958 -> __.CSR0958
    | RISCV64.CSR0959 -> __.CSR0959
    | RISCV64.CSR0960 -> __.CSR0960
    | RISCV64.CSR0961 -> __.CSR0961
    | RISCV64.CSR0962 -> __.CSR0962
    | RISCV64.CSR0963 -> __.CSR0963
    | RISCV64.CSR0964 -> __.CSR0964
    | RISCV64.CSR0965 -> __.CSR0965
    | RISCV64.CSR0966 -> __.CSR0966
    | RISCV64.CSR0967 -> __.CSR0967
    | RISCV64.CSR0968 -> __.CSR0968
    | RISCV64.CSR0969 -> __.CSR0969
    | RISCV64.CSR0970 -> __.CSR0970
    | RISCV64.CSR0971 -> __.CSR0971
    | RISCV64.CSR0972 -> __.CSR0972
    | RISCV64.CSR0973 -> __.CSR0973
    | RISCV64.CSR0974 -> __.CSR0974
    | RISCV64.CSR0975 -> __.CSR0975
    | RISCV64.CSR0976 -> __.CSR0976
    | RISCV64.CSR0977 -> __.CSR0977
    | RISCV64.CSR0978 -> __.CSR0978
    | RISCV64.CSR0979 -> __.CSR0979
    | RISCV64.CSR0980 -> __.CSR0980
    | RISCV64.CSR0981 -> __.CSR0981
    | RISCV64.CSR0982 -> __.CSR0982
    | RISCV64.CSR0983 -> __.CSR0983
    | RISCV64.CSR0984 -> __.CSR0984
    | RISCV64.CSR0985 -> __.CSR0985
    | RISCV64.CSR0986 -> __.CSR0986
    | RISCV64.CSR0987 -> __.CSR0987
    | RISCV64.CSR0988 -> __.CSR0988
    | RISCV64.CSR0989 -> __.CSR0989
    | RISCV64.CSR0990 -> __.CSR0990
    | RISCV64.CSR0991 -> __.CSR0991
    | RISCV64.CSR0992 -> __.CSR0992
    | RISCV64.CSR0993 -> __.CSR0993
    | RISCV64.CSR0994 -> __.CSR0994
    | RISCV64.CSR0995 -> __.CSR0995
    | RISCV64.CSR0996 -> __.CSR0996
    | RISCV64.CSR0997 -> __.CSR0997
    | RISCV64.CSR0998 -> __.CSR0998
    | RISCV64.CSR0999 -> __.CSR0999
    | RISCV64.CSR1000 -> __.CSR1000
    | RISCV64.CSR1001 -> __.CSR1001
    | RISCV64.CSR1002 -> __.CSR1002
    | RISCV64.CSR1003 -> __.CSR1003
    | RISCV64.CSR1004 -> __.CSR1004
    | RISCV64.CSR1005 -> __.CSR1005
    | RISCV64.CSR1006 -> __.CSR1006
    | RISCV64.CSR1007 -> __.CSR1007
    | RISCV64.CSR2145 -> __.CSR2145
    | RISCV64.CSR2617 -> __.CSR2617
    | RISCV64.CSR2816 -> __.CSR2816
    | RISCV64.CSR2818 -> __.CSR2818
    | RISCV64.CSR2819 -> __.CSR2819
    | RISCV64.CSR2820 -> __.CSR2820
    | RISCV64.CSR2821 -> __.CSR2821
    | RISCV64.CSR2822 -> __.CSR2822
    | RISCV64.CSR2823 -> __.CSR2823
    | RISCV64.CSR2824 -> __.CSR2824
    | RISCV64.CSR2825 -> __.CSR2825
    | RISCV64.CSR2826 -> __.CSR2826
    | RISCV64.CSR2827 -> __.CSR2827
    | RISCV64.CSR2828 -> __.CSR2828
    | RISCV64.CSR2829 -> __.CSR2829
    | RISCV64.CSR2830 -> __.CSR2830
    | RISCV64.CSR2831 -> __.CSR2831
    | RISCV64.CSR2832 -> __.CSR2832
    | RISCV64.CSR2833 -> __.CSR2833
    | RISCV64.CSR2834 -> __.CSR2834
    | RISCV64.CSR2835 -> __.CSR2835
    | RISCV64.CSR2836 -> __.CSR2836
    | RISCV64.CSR2837 -> __.CSR2837
    | RISCV64.CSR2838 -> __.CSR2838
    | RISCV64.CSR2839 -> __.CSR2839
    | RISCV64.CSR2840 -> __.CSR2840
    | RISCV64.CSR2841 -> __.CSR2841
    | RISCV64.CSR2842 -> __.CSR2842
    | RISCV64.CSR2843 -> __.CSR2843
    | RISCV64.CSR2844 -> __.CSR2844
    | RISCV64.CSR2845 -> __.CSR2845
    | RISCV64.CSR2846 -> __.CSR2846
    | RISCV64.CSR2847 -> __.CSR2847
    | RISCV64.CSR2945 -> __.CSR2945
    | RISCV64.CSR0800 -> __.CSR0800
    | RISCV64.CSR0803 -> __.CSR0803
    | RISCV64.CSR0804 -> __.CSR0804
    | RISCV64.CSR0805 -> __.CSR0805
    | RISCV64.CSR0806 -> __.CSR0806
    | RISCV64.CSR0807 -> __.CSR0807
    | RISCV64.CSR0808 -> __.CSR0808
    | RISCV64.CSR0809 -> __.CSR0809
    | RISCV64.CSR0810 -> __.CSR0810
    | RISCV64.CSR0811 -> __.CSR0811
    | RISCV64.CSR0812 -> __.CSR0812
    | RISCV64.CSR0813 -> __.CSR0813
    | RISCV64.CSR0814 -> __.CSR0814
    | RISCV64.CSR0815 -> __.CSR0815
    | RISCV64.CSR0816 -> __.CSR0816
    | RISCV64.CSR0817 -> __.CSR0817
    | RISCV64.CSR0818 -> __.CSR0818
    | RISCV64.CSR0819 -> __.CSR0819
    | RISCV64.CSR0820 -> __.CSR0820
    | RISCV64.CSR0821 -> __.CSR0821
    | RISCV64.CSR0822 -> __.CSR0822
    | RISCV64.CSR0823 -> __.CSR0823
    | RISCV64.CSR0824 -> __.CSR0824
    | RISCV64.CSR0825 -> __.CSR0825
    | RISCV64.CSR0826 -> __.CSR0826
    | RISCV64.CSR0827 -> __.CSR0827
    | RISCV64.CSR0828 -> __.CSR0828
    | RISCV64.CSR0829 -> __.CSR0829
    | RISCV64.CSR0830 -> __.CSR0830
    | RISCV64.CSR0831 -> __.CSR0831
    | RISCV64.CSR1952 -> __.CSR1952
    | RISCV64.CSR1953 -> __.CSR1953
    | RISCV64.CSR1954 -> __.CSR1954
    | RISCV64.CSR1955 -> __.CSR1955
    | RISCV64.CSR1968 -> __.CSR1968
    | RISCV64.CSR1969 -> __.CSR1969
    | RISCV64.CSR1970 -> __.CSR1970
    | RISCV64.CSR1971 -> __.CSR1971
    | _ -> raise UnhandledRegExprException

// vim: set tw=80 sts=2 sw=2:
