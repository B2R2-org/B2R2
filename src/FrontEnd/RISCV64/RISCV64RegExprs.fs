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

namespace B2R2.FrontEnd.RISCV64

open B2R2
open B2R2.FrontEnd.BinLifter
open B2R2.FrontEnd.BinLifter.LiftingUtils
open B2R2.BinIR.LowUIR
open B2R2.BinIR.LowUIR.AST.InfixOp

type RegExprs (wordSize) =
  let var sz t name = AST.var sz t name

  (* RISCV64. *)
  let regType = WordSize.toRegType wordSize
  let fflags = var 32<rt> (Register.toRegID Register.FFLAGS) "FFLAGS"
  let frm = var 32<rt> (Register.toRegID Register.FRM) "FRM"

  member val X0 = var regType (Register.toRegID Register.X0) "X0" with get
  member val X1 = var regType (Register.toRegID Register.X1) "X1" with get
  member val X2 = var regType (Register.toRegID Register.X2) "X2" with get
  member val X3 = var regType (Register.toRegID Register.X3) "X3" with get
  member val X4 = var regType (Register.toRegID Register.X4) "X4" with get
  member val X5 = var regType (Register.toRegID Register.X5) "X5" with get
  member val X6 = var regType (Register.toRegID Register.X6) "X6" with get
  member val X7 = var regType (Register.toRegID Register.X7) "X7" with get
  member val X8 = var regType (Register.toRegID Register.X8) "X8" with get
  member val X9 = var regType (Register.toRegID Register.X9) "X9" with get
  member val X10 = var regType (Register.toRegID Register.X10) "X10" with get
  member val X11 = var regType (Register.toRegID Register.X11) "X11" with get
  member val X12 = var regType (Register.toRegID Register.X12) "X12" with get
  member val X13 = var regType (Register.toRegID Register.X13) "X13" with get
  member val X14 = var regType (Register.toRegID Register.X14) "X14" with get
  member val X15 = var regType (Register.toRegID Register.X15) "X15" with get
  member val X16 = var regType (Register.toRegID Register.X16) "X16" with get
  member val X17 = var regType (Register.toRegID Register.X17) "X17" with get
  member val X18 = var regType (Register.toRegID Register.X18) "X18" with get
  member val X19 = var regType (Register.toRegID Register.X19) "X19" with get
  member val X20 = var regType (Register.toRegID Register.X20) "X20" with get
  member val X21 = var regType (Register.toRegID Register.X21) "X21" with get
  member val X22 = var regType (Register.toRegID Register.X22) "X22" with get
  member val X23 = var regType (Register.toRegID Register.X23) "X23" with get
  member val X24 = var regType (Register.toRegID Register.X24) "X24" with get
  member val X25 = var regType (Register.toRegID Register.X25) "X25" with get
  member val X26 = var regType (Register.toRegID Register.X26) "X26" with get
  member val X27 = var regType (Register.toRegID Register.X27) "X27" with get
  member val X28 = var regType (Register.toRegID Register.X28) "X28" with get
  member val X29 = var regType (Register.toRegID Register.X29) "X29" with get
  member val X30 = var regType (Register.toRegID Register.X30) "X30" with get
  member val X31 = var regType (Register.toRegID Register.X31) "X31" with get

  member val F0 = var regType (Register.toRegID Register.F0) "F0" with get
  member val F1 = var regType (Register.toRegID Register.F1) "F1" with get
  member val F2 = var regType (Register.toRegID Register.F2) "F2" with get
  member val F3 = var regType (Register.toRegID Register.F3) "F3" with get
  member val F4 = var regType (Register.toRegID Register.F4) "F4" with get
  member val F5 = var regType (Register.toRegID Register.F5) "F5" with get
  member val F6 = var regType (Register.toRegID Register.F6) "F6" with get
  member val F7 = var regType (Register.toRegID Register.F7) "F7" with get
  member val F8 = var regType (Register.toRegID Register.F8) "F8" with get
  member val F9 = var regType (Register.toRegID Register.F9) "F9" with get
  member val F10 = var regType (Register.toRegID Register.F10) "F10" with get
  member val F11 = var regType (Register.toRegID Register.F11) "F11" with get
  member val F12 = var regType (Register.toRegID Register.F12) "F12" with get
  member val F13 = var regType (Register.toRegID Register.F13) "F13" with get
  member val F14 = var regType (Register.toRegID Register.F14) "F14" with get
  member val F15 = var regType (Register.toRegID Register.F15) "F15" with get
  member val F16 = var regType (Register.toRegID Register.F16) "F16" with get
  member val F17 = var regType (Register.toRegID Register.F17) "F17" with get
  member val F18 = var regType (Register.toRegID Register.F18) "F18" with get
  member val F19 = var regType (Register.toRegID Register.F19) "F19" with get
  member val F20 = var regType (Register.toRegID Register.F20) "F20" with get
  member val F21 = var regType (Register.toRegID Register.F21) "F21" with get
  member val F22 = var regType (Register.toRegID Register.F22) "F22" with get
  member val F23 = var regType (Register.toRegID Register.F23) "F23" with get
  member val F24 = var regType (Register.toRegID Register.F24) "F24" with get
  member val F25 = var regType (Register.toRegID Register.F25) "F25" with get
  member val F26 = var regType (Register.toRegID Register.F26) "F26" with get
  member val F27 = var regType (Register.toRegID Register.F27) "F27" with get
  member val F28 = var regType (Register.toRegID Register.F28) "F28" with get
  member val F29 = var regType (Register.toRegID Register.F29) "F29" with get
  member val F30 = var regType (Register.toRegID Register.F30) "F30" with get
  member val F31 = var regType (Register.toRegID Register.F31) "F31" with get

  member val PC = AST.pcvar regType "PC" with get
  member val RC = var 1<rt> (Register.toRegID Register.RC) "RC" with get
  member val FFLAGS = fflags with get
  member val FRM = frm with get
  member val FCSR =
    (fflags .& (numI32 0b11111 32<rt>))
    .| ((frm .& (numI32 0b111 32<rt>)) << numI32 5 32<rt>) with get

  member val CSR0768 =
    var regType (Register.toRegID Register.CSR0768) "CSR0768" with get
  member val CSR0769 =
    var regType (Register.toRegID Register.CSR0769) "CSR0769" with get
  member val CSR0770 =
    var regType (Register.toRegID Register.CSR0770) "CSR0770" with get
  member val CSR0771 =
    var regType (Register.toRegID Register.CSR0771) "CSR0771" with get
  member val CSR0772 =
    var regType (Register.toRegID Register.CSR0772) "CSR0772" with get
  member val CSR0773 =
    var regType (Register.toRegID Register.CSR0773) "CSR0773" with get
  member val CSR0784 =
    var regType (Register.toRegID Register.CSR0784) "CSR0784" with get
  member val CSR0832 =
    var regType (Register.toRegID Register.CSR0832) "CSR0832" with get
  member val CSR0833 =
    var regType (Register.toRegID Register.CSR0833) "CSR0833" with get
  member val CSR0834 =
    var regType (Register.toRegID Register.CSR0834) "CSR0834" with get
  member val CSR0835 =
    var regType (Register.toRegID Register.CSR0835) "CSR0835" with get
  member val CSR0836 =
    var regType (Register.toRegID Register.CSR0836) "CSR0836" with get
  member val CSR0842 =
    var regType (Register.toRegID Register.CSR0842) "CSR0842" with get
  member val CSR0843 =
    var regType (Register.toRegID Register.CSR0843) "CSR0843" with get
  member val CSR3114 =
    var regType (Register.toRegID Register.CSR3114) "CSR3114" with get
  member val CSR3787 =
    var regType (Register.toRegID Register.CSR3787) "CSR3787" with get
  member val CSR3857 =
    var regType (Register.toRegID Register.CSR3857) "CSR3857" with get
  member val CSR3858 =
    var regType (Register.toRegID Register.CSR3858) "CSR3858" with get
  member val CSR3859 =
    var regType (Register.toRegID Register.CSR3859) "CSR3859" with get
  member val CSR3860 =
    var regType (Register.toRegID Register.CSR3860) "CSR3860" with get
  member val CSR0928 =
    var regType (Register.toRegID Register.CSR0928) "CSR0928" with get
  member val CSR0930 =
    var regType (Register.toRegID Register.CSR0930) "CSR0930" with get
  member val CSR0932 =
    var regType (Register.toRegID Register.CSR0932) "CSR0932" with get
  member val CSR0934 =
    var regType (Register.toRegID Register.CSR0934) "CSR0934" with get
  member val CSR0936 =
    var regType (Register.toRegID Register.CSR0936) "CSR0936" with get
  member val CSR0938 =
    var regType (Register.toRegID Register.CSR0938) "CSR0938" with get
  member val CSR0940 =
    var regType (Register.toRegID Register.CSR0940) "CSR0940" with get
  member val CSR0942 =
    var regType (Register.toRegID Register.CSR0942) "CSR0942" with get
  member val CSR0944 =
    var regType (Register.toRegID Register.CSR0944) "CSR0944" with get
  member val CSR0945 =
    var regType (Register.toRegID Register.CSR0945) "CSR0945" with get
  member val CSR0946 =
    var regType (Register.toRegID Register.CSR0946) "CSR0946" with get
  member val CSR0947 =
    var regType (Register.toRegID Register.CSR0947) "CSR0947" with get
  member val CSR0948 =
    var regType (Register.toRegID Register.CSR0948) "CSR0948" with get
  member val CSR0949 =
    var regType (Register.toRegID Register.CSR0949) "CSR0949" with get
  member val CSR0950 =
    var regType (Register.toRegID Register.CSR0950) "CSR0950" with get
  member val CSR0951 =
    var regType (Register.toRegID Register.CSR0951) "CSR0951" with get
  member val CSR0952 =
    var regType (Register.toRegID Register.CSR0952) "CSR0952" with get
  member val CSR0953 =
    var regType (Register.toRegID Register.CSR0953) "CSR0953" with get
  member val CSR0954 =
    var regType (Register.toRegID Register.CSR0954) "CSR0954" with get
  member val CSR0955 =
    var regType (Register.toRegID Register.CSR0955) "CSR0955" with get
  member val CSR0956 =
    var regType (Register.toRegID Register.CSR0956) "CSR0956" with get
  member val CSR0957 =
    var regType (Register.toRegID Register.CSR0957) "CSR0957" with get
  member val CSR0958 =
    var regType (Register.toRegID Register.CSR0958) "CSR0958" with get
  member val CSR0959 =
    var regType (Register.toRegID Register.CSR0959) "CSR0959" with get
  member val CSR0960 =
    var regType (Register.toRegID Register.CSR0960) "CSR0960" with get
  member val CSR0961 =
    var regType (Register.toRegID Register.CSR0961) "CSR0961" with get
  member val CSR0962 =
    var regType (Register.toRegID Register.CSR0962) "CSR0962" with get
  member val CSR0963 =
    var regType (Register.toRegID Register.CSR0963) "CSR0963" with get
  member val CSR0964 =
    var regType (Register.toRegID Register.CSR0964) "CSR0964" with get
  member val CSR0965 =
    var regType (Register.toRegID Register.CSR0965) "CSR0965" with get
  member val CSR0966 =
    var regType (Register.toRegID Register.CSR0966) "CSR0966" with get
  member val CSR0967 =
    var regType (Register.toRegID Register.CSR0967) "CSR0967" with get
  member val CSR0968 =
    var regType (Register.toRegID Register.CSR0968) "CSR0968" with get
  member val CSR0969 =
    var regType (Register.toRegID Register.CSR0969) "CSR0969" with get
  member val CSR0970 =
    var regType (Register.toRegID Register.CSR0970) "CSR0970" with get
  member val CSR0971 =
    var regType (Register.toRegID Register.CSR0971) "CSR0971" with get
  member val CSR0972 =
    var regType (Register.toRegID Register.CSR0972) "CSR0972" with get
  member val CSR0973 =
    var regType (Register.toRegID Register.CSR0973) "CSR0973" with get
  member val CSR0974 =
    var regType (Register.toRegID Register.CSR0974) "CSR0974" with get
  member val CSR0975 =
    var regType (Register.toRegID Register.CSR0975) "CSR0975" with get
  member val CSR0976 =
    var regType (Register.toRegID Register.CSR0976) "CSR0976" with get
  member val CSR0977 =
    var regType (Register.toRegID Register.CSR0977) "CSR0977" with get
  member val CSR0978 =
    var regType (Register.toRegID Register.CSR0978) "CSR0978" with get
  member val CSR0979 =
    var regType (Register.toRegID Register.CSR0979) "CSR0979" with get
  member val CSR0980 =
    var regType (Register.toRegID Register.CSR0980) "CSR0980" with get
  member val CSR0981 =
    var regType (Register.toRegID Register.CSR0981) "CSR0981" with get
  member val CSR0982 =
    var regType (Register.toRegID Register.CSR0982) "CSR0982" with get
  member val CSR0983 =
    var regType (Register.toRegID Register.CSR0983) "CSR0983" with get
  member val CSR0984 =
    var regType (Register.toRegID Register.CSR0984) "CSR0984" with get
  member val CSR0985 =
    var regType (Register.toRegID Register.CSR0985) "CSR0985" with get
  member val CSR0986 =
    var regType (Register.toRegID Register.CSR0986) "CSR0986" with get
  member val CSR0987 =
    var regType (Register.toRegID Register.CSR0987) "CSR0987" with get
  member val CSR0988 =
    var regType (Register.toRegID Register.CSR0988) "CSR0988" with get
  member val CSR0989 =
    var regType (Register.toRegID Register.CSR0989) "CSR0989" with get
  member val CSR0990 =
    var regType (Register.toRegID Register.CSR0990) "CSR0990" with get
  member val CSR0991 =
    var regType (Register.toRegID Register.CSR0991) "CSR0991" with get
  member val CSR0992 =
    var regType (Register.toRegID Register.CSR0992) "CSR0992" with get
  member val CSR0993 =
    var regType (Register.toRegID Register.CSR0993) "CSR0993" with get
  member val CSR0994 =
    var regType (Register.toRegID Register.CSR0994) "CSR0994" with get
  member val CSR0995 =
    var regType (Register.toRegID Register.CSR0995) "CSR0995" with get
  member val CSR0996 =
    var regType (Register.toRegID Register.CSR0996) "CSR0996" with get
  member val CSR0997 =
    var regType (Register.toRegID Register.CSR0997) "CSR0997" with get
  member val CSR0998 =
    var regType (Register.toRegID Register.CSR0998) "CSR0998" with get
  member val CSR0999 =
    var regType (Register.toRegID Register.CSR0999) "CSR0999" with get
  member val CSR1000 =
    var regType (Register.toRegID Register.CSR1000) "CSR1000" with get
  member val CSR1001 =
    var regType (Register.toRegID Register.CSR1001) "CSR1001" with get
  member val CSR1002 =
    var regType (Register.toRegID Register.CSR1002) "CSR1002" with get
  member val CSR1003 =
    var regType (Register.toRegID Register.CSR1003) "CSR1003" with get
  member val CSR1004 =
    var regType (Register.toRegID Register.CSR1004) "CSR1004" with get
  member val CSR1005 =
    var regType (Register.toRegID Register.CSR1005) "CSR1005" with get
  member val CSR1006 =
    var regType (Register.toRegID Register.CSR1006) "CSR1006" with get
  member val CSR1007 =
    var regType (Register.toRegID Register.CSR1007) "CSR1007" with get
  member val CSR2145 =
    var regType (Register.toRegID Register.CSR2145) "CSR2145" with get
  member val CSR2617 =
    var regType (Register.toRegID Register.CSR2617) "CSR2617" with get
  member val CSR2816 =
    var regType (Register.toRegID Register.CSR2816) "CSR2816" with get
  member val CSR2818 =
    var regType (Register.toRegID Register.CSR2818) "CSR2818" with get
  member val CSR2819 =
    var regType (Register.toRegID Register.CSR2819) "CSR2819" with get
  member val CSR2820 =
    var regType (Register.toRegID Register.CSR2820) "CSR2820" with get
  member val CSR2821 =
    var regType (Register.toRegID Register.CSR2821) "CSR2821" with get
  member val CSR2822 =
    var regType (Register.toRegID Register.CSR2822) "CSR2822" with get
  member val CSR2823 =
    var regType (Register.toRegID Register.CSR2823) "CSR2823" with get
  member val CSR2824 =
    var regType (Register.toRegID Register.CSR2824) "CSR2824" with get
  member val CSR2825 =
    var regType (Register.toRegID Register.CSR2825) "CSR2825" with get
  member val CSR2826 =
    var regType (Register.toRegID Register.CSR2826) "CSR2826" with get
  member val CSR2827 =
    var regType (Register.toRegID Register.CSR2827) "CSR2827" with get
  member val CSR2828 =
    var regType (Register.toRegID Register.CSR2828) "CSR2828" with get
  member val CSR2829 =
    var regType (Register.toRegID Register.CSR2829) "CSR2829" with get
  member val CSR2830 =
    var regType (Register.toRegID Register.CSR2830) "CSR2830" with get
  member val CSR2831 =
    var regType (Register.toRegID Register.CSR2831) "CSR2831" with get
  member val CSR2832 =
    var regType (Register.toRegID Register.CSR2832) "CSR2832" with get
  member val CSR2833 =
    var regType (Register.toRegID Register.CSR2833) "CSR2833" with get
  member val CSR2834 =
    var regType (Register.toRegID Register.CSR2834) "CSR2834" with get
  member val CSR2835 =
    var regType (Register.toRegID Register.CSR2835) "CSR2835" with get
  member val CSR2836 =
    var regType (Register.toRegID Register.CSR2836) "CSR2836" with get
  member val CSR2837 =
    var regType (Register.toRegID Register.CSR2837) "CSR2837" with get
  member val CSR2838 =
    var regType (Register.toRegID Register.CSR2838) "CSR2838" with get
  member val CSR2839 =
    var regType (Register.toRegID Register.CSR2839) "CSR2839" with get
  member val CSR2840 =
    var regType (Register.toRegID Register.CSR2840) "CSR2840" with get
  member val CSR2841 =
    var regType (Register.toRegID Register.CSR2841) "CSR2841" with get
  member val CSR2842 =
    var regType (Register.toRegID Register.CSR2842) "CSR2842" with get
  member val CSR2843 =
    var regType (Register.toRegID Register.CSR2843) "CSR2843" with get
  member val CSR2844 =
    var regType (Register.toRegID Register.CSR2844) "CSR2844" with get
  member val CSR2845 =
    var regType (Register.toRegID Register.CSR2845) "CSR2845" with get
  member val CSR2846 =
    var regType (Register.toRegID Register.CSR2846) "CSR2846" with get
  member val CSR2847 =
    var regType (Register.toRegID Register.CSR2847) "CSR2847" with get
  member val CSR2945 =
    var regType (Register.toRegID Register.CSR2945) "CSR2945" with get
  member val CSR0800 =
    var regType (Register.toRegID Register.CSR0800) "CSR0800" with get
  member val CSR0803 =
    var regType (Register.toRegID Register.CSR0803) "CSR0803" with get
  member val CSR0804 =
    var regType (Register.toRegID Register.CSR0804) "CSR0804" with get
  member val CSR0805 =
    var regType (Register.toRegID Register.CSR0805) "CSR0805" with get
  member val CSR0806 =
    var regType (Register.toRegID Register.CSR0806) "CSR0806" with get
  member val CSR0807 =
    var regType (Register.toRegID Register.CSR0807) "CSR0807" with get
  member val CSR0808 =
    var regType (Register.toRegID Register.CSR0808) "CSR0808" with get
  member val CSR0809 =
    var regType (Register.toRegID Register.CSR0809) "CSR0809" with get
  member val CSR0810 =
    var regType (Register.toRegID Register.CSR0810) "CSR0810" with get
  member val CSR0811 =
    var regType (Register.toRegID Register.CSR0811) "CSR0811" with get
  member val CSR0812 =
    var regType (Register.toRegID Register.CSR0812) "CSR0812" with get
  member val CSR0813 =
    var regType (Register.toRegID Register.CSR0813) "CSR0813" with get
  member val CSR0814 =
    var regType (Register.toRegID Register.CSR0814) "CSR0814" with get
  member val CSR0815 =
    var regType (Register.toRegID Register.CSR0815) "CSR0815" with get
  member val CSR0816 =
    var regType (Register.toRegID Register.CSR0816) "CSR0816" with get
  member val CSR0817 =
    var regType (Register.toRegID Register.CSR0817) "CSR0817" with get
  member val CSR0818 =
    var regType (Register.toRegID Register.CSR0818) "CSR0818" with get
  member val CSR0819 =
    var regType (Register.toRegID Register.CSR0819) "CSR0819" with get
  member val CSR0820 =
    var regType (Register.toRegID Register.CSR0820) "CSR0820" with get
  member val CSR0821 =
    var regType (Register.toRegID Register.CSR0821) "CSR0821" with get
  member val CSR0822 =
    var regType (Register.toRegID Register.CSR0822) "CSR0822" with get
  member val CSR0823 =
    var regType (Register.toRegID Register.CSR0823) "CSR0823" with get
  member val CSR0824 =
    var regType (Register.toRegID Register.CSR0824) "CSR0824" with get
  member val CSR0825 =
    var regType (Register.toRegID Register.CSR0825) "CSR0825" with get
  member val CSR0826 =
    var regType (Register.toRegID Register.CSR0826) "CSR0826" with get
  member val CSR0827 =
    var regType (Register.toRegID Register.CSR0827) "CSR0827" with get
  member val CSR0828 =
    var regType (Register.toRegID Register.CSR0828) "CSR0828" with get
  member val CSR0829 =
    var regType (Register.toRegID Register.CSR0829) "CSR0829" with get
  member val CSR0830 =
    var regType (Register.toRegID Register.CSR0830) "CSR0830" with get
  member val CSR0831 =
    var regType (Register.toRegID Register.CSR0831) "CSR0831" with get
  member val CSR1952 =
    var regType (Register.toRegID Register.CSR1952) "CSR1952" with get
  member val CSR1953 =
    var regType (Register.toRegID Register.CSR1953) "CSR1953" with get
  member val CSR1954 =
    var regType (Register.toRegID Register.CSR1954) "CSR1954" with get
  member val CSR1955 =
    var regType (Register.toRegID Register.CSR1955) "CSR1955" with get
  member val CSR1968 =
    var regType (Register.toRegID Register.CSR1968) "CSR1968" with get
  member val CSR1969 =
    var regType (Register.toRegID Register.CSR1969) "CSR1969" with get
  member val CSR1970 =
    var regType (Register.toRegID Register.CSR1970) "CSR1970" with get
  member val CSR1971 =
    var regType (Register.toRegID Register.CSR1971) "CSR1971" with get

  member __.GetRegVar name =
    match name with
    | Register.PC  -> __.PC
    | Register.RC -> __.RC
    | Register.X0 -> __.X0
    | Register.X1 -> __.X1
    | Register.X2 -> __.X2
    | Register.X3 -> __.X3
    | Register.X4 -> __.X4
    | Register.X5 -> __.X5
    | Register.X6 -> __.X6
    | Register.X7 -> __.X7
    | Register.X8 -> __.X8
    | Register.X9 -> __.X9
    | Register.X10 -> __.X10
    | Register.X11 -> __.X11
    | Register.X12 -> __.X12
    | Register.X13 -> __.X13
    | Register.X14 -> __.X14
    | Register.X15 -> __.X15
    | Register.X16 -> __.X16
    | Register.X17 -> __.X17
    | Register.X18 -> __.X18
    | Register.X19 -> __.X19
    | Register.X20 -> __.X20
    | Register.X21 -> __.X21
    | Register.X22 -> __.X22
    | Register.X23 -> __.X23
    | Register.X24 -> __.X24
    | Register.X25 -> __.X25
    | Register.X26 -> __.X26
    | Register.X27 -> __.X27
    | Register.X28 -> __.X28
    | Register.X29 -> __.X29
    | Register.X30 -> __.X30
    | Register.X31 -> __.X31
    | Register.F0 -> __.F0
    | Register.F1 -> __.F1
    | Register.F2 -> __.F2
    | Register.F3 -> __.F3
    | Register.F4 -> __.F4
    | Register.F5 -> __.F5
    | Register.F6 -> __.F6
    | Register.F7 -> __.F7
    | Register.F8 -> __.F8
    | Register.F9 -> __.F9
    | Register.F10 -> __.F10
    | Register.F11 -> __.F11
    | Register.F12 -> __.F12
    | Register.F13 -> __.F13
    | Register.F14 -> __.F14
    | Register.F15 -> __.F15
    | Register.F16 -> __.F16
    | Register.F17 -> __.F17
    | Register.F18 -> __.F18
    | Register.F19 -> __.F19
    | Register.F20 -> __.F20
    | Register.F21 -> __.F21
    | Register.F22 -> __.F22
    | Register.F23 -> __.F23
    | Register.F24 -> __.F24
    | Register.F25 -> __.F25
    | Register.F26 -> __.F26
    | Register.F27 -> __.F27
    | Register.F28 -> __.F28
    | Register.F29 -> __.F29
    | Register.F30 -> __.F30
    | Register.F31 -> __.F31
    | Register.FFLAGS -> __.FFLAGS
    | Register.FRM -> __.FRM
    | Register.FCSR -> __.FCSR
    | Register.CSR0768 -> __.CSR0768
    | Register.CSR0769 -> __.CSR0769
    | Register.CSR0770 -> __.CSR0770
    | Register.CSR0771 -> __.CSR0771
    | Register.CSR0772 -> __.CSR0772
    | Register.CSR0773 -> __.CSR0773
    | Register.CSR0784 -> __.CSR0784
    | Register.CSR0832 -> __.CSR0832
    | Register.CSR0833 -> __.CSR0833
    | Register.CSR0834 -> __.CSR0834
    | Register.CSR0835 -> __.CSR0835
    | Register.CSR0836 -> __.CSR0836
    | Register.CSR0842 -> __.CSR0842
    | Register.CSR0843 -> __.CSR0843
    | Register.CSR3114 -> __.CSR3114
    | Register.CSR3787 -> __.CSR3787
    | Register.CSR3857 -> __.CSR3857
    | Register.CSR3858 -> __.CSR3858
    | Register.CSR3859 -> __.CSR3859
    | Register.CSR3860 -> __.CSR3860
    | Register.CSR0928 -> __.CSR0928
    | Register.CSR0930 -> __.CSR0930
    | Register.CSR0932 -> __.CSR0932
    | Register.CSR0934 -> __.CSR0934
    | Register.CSR0936 -> __.CSR0936
    | Register.CSR0938 -> __.CSR0938
    | Register.CSR0940 -> __.CSR0940
    | Register.CSR0942 -> __.CSR0942
    | Register.CSR0944 -> __.CSR0944
    | Register.CSR0945 -> __.CSR0945
    | Register.CSR0946 -> __.CSR0946
    | Register.CSR0947 -> __.CSR0947
    | Register.CSR0948 -> __.CSR0948
    | Register.CSR0949 -> __.CSR0949
    | Register.CSR0950 -> __.CSR0950
    | Register.CSR0951 -> __.CSR0951
    | Register.CSR0952 -> __.CSR0952
    | Register.CSR0953 -> __.CSR0953
    | Register.CSR0954 -> __.CSR0954
    | Register.CSR0955 -> __.CSR0955
    | Register.CSR0956 -> __.CSR0956
    | Register.CSR0957 -> __.CSR0957
    | Register.CSR0958 -> __.CSR0958
    | Register.CSR0959 -> __.CSR0959
    | Register.CSR0960 -> __.CSR0960
    | Register.CSR0961 -> __.CSR0961
    | Register.CSR0962 -> __.CSR0962
    | Register.CSR0963 -> __.CSR0963
    | Register.CSR0964 -> __.CSR0964
    | Register.CSR0965 -> __.CSR0965
    | Register.CSR0966 -> __.CSR0966
    | Register.CSR0967 -> __.CSR0967
    | Register.CSR0968 -> __.CSR0968
    | Register.CSR0969 -> __.CSR0969
    | Register.CSR0970 -> __.CSR0970
    | Register.CSR0971 -> __.CSR0971
    | Register.CSR0972 -> __.CSR0972
    | Register.CSR0973 -> __.CSR0973
    | Register.CSR0974 -> __.CSR0974
    | Register.CSR0975 -> __.CSR0975
    | Register.CSR0976 -> __.CSR0976
    | Register.CSR0977 -> __.CSR0977
    | Register.CSR0978 -> __.CSR0978
    | Register.CSR0979 -> __.CSR0979
    | Register.CSR0980 -> __.CSR0980
    | Register.CSR0981 -> __.CSR0981
    | Register.CSR0982 -> __.CSR0982
    | Register.CSR0983 -> __.CSR0983
    | Register.CSR0984 -> __.CSR0984
    | Register.CSR0985 -> __.CSR0985
    | Register.CSR0986 -> __.CSR0986
    | Register.CSR0987 -> __.CSR0987
    | Register.CSR0988 -> __.CSR0988
    | Register.CSR0989 -> __.CSR0989
    | Register.CSR0990 -> __.CSR0990
    | Register.CSR0991 -> __.CSR0991
    | Register.CSR0992 -> __.CSR0992
    | Register.CSR0993 -> __.CSR0993
    | Register.CSR0994 -> __.CSR0994
    | Register.CSR0995 -> __.CSR0995
    | Register.CSR0996 -> __.CSR0996
    | Register.CSR0997 -> __.CSR0997
    | Register.CSR0998 -> __.CSR0998
    | Register.CSR0999 -> __.CSR0999
    | Register.CSR1000 -> __.CSR1000
    | Register.CSR1001 -> __.CSR1001
    | Register.CSR1002 -> __.CSR1002
    | Register.CSR1003 -> __.CSR1003
    | Register.CSR1004 -> __.CSR1004
    | Register.CSR1005 -> __.CSR1005
    | Register.CSR1006 -> __.CSR1006
    | Register.CSR1007 -> __.CSR1007
    | Register.CSR2145 -> __.CSR2145
    | Register.CSR2617 -> __.CSR2617
    | Register.CSR2816 -> __.CSR2816
    | Register.CSR2818 -> __.CSR2818
    | Register.CSR2819 -> __.CSR2819
    | Register.CSR2820 -> __.CSR2820
    | Register.CSR2821 -> __.CSR2821
    | Register.CSR2822 -> __.CSR2822
    | Register.CSR2823 -> __.CSR2823
    | Register.CSR2824 -> __.CSR2824
    | Register.CSR2825 -> __.CSR2825
    | Register.CSR2826 -> __.CSR2826
    | Register.CSR2827 -> __.CSR2827
    | Register.CSR2828 -> __.CSR2828
    | Register.CSR2829 -> __.CSR2829
    | Register.CSR2830 -> __.CSR2830
    | Register.CSR2831 -> __.CSR2831
    | Register.CSR2832 -> __.CSR2832
    | Register.CSR2833 -> __.CSR2833
    | Register.CSR2834 -> __.CSR2834
    | Register.CSR2835 -> __.CSR2835
    | Register.CSR2836 -> __.CSR2836
    | Register.CSR2837 -> __.CSR2837
    | Register.CSR2838 -> __.CSR2838
    | Register.CSR2839 -> __.CSR2839
    | Register.CSR2840 -> __.CSR2840
    | Register.CSR2841 -> __.CSR2841
    | Register.CSR2842 -> __.CSR2842
    | Register.CSR2843 -> __.CSR2843
    | Register.CSR2844 -> __.CSR2844
    | Register.CSR2845 -> __.CSR2845
    | Register.CSR2846 -> __.CSR2846
    | Register.CSR2847 -> __.CSR2847
    | Register.CSR2945 -> __.CSR2945
    | Register.CSR0800 -> __.CSR0800
    | Register.CSR0803 -> __.CSR0803
    | Register.CSR0804 -> __.CSR0804
    | Register.CSR0805 -> __.CSR0805
    | Register.CSR0806 -> __.CSR0806
    | Register.CSR0807 -> __.CSR0807
    | Register.CSR0808 -> __.CSR0808
    | Register.CSR0809 -> __.CSR0809
    | Register.CSR0810 -> __.CSR0810
    | Register.CSR0811 -> __.CSR0811
    | Register.CSR0812 -> __.CSR0812
    | Register.CSR0813 -> __.CSR0813
    | Register.CSR0814 -> __.CSR0814
    | Register.CSR0815 -> __.CSR0815
    | Register.CSR0816 -> __.CSR0816
    | Register.CSR0817 -> __.CSR0817
    | Register.CSR0818 -> __.CSR0818
    | Register.CSR0819 -> __.CSR0819
    | Register.CSR0820 -> __.CSR0820
    | Register.CSR0821 -> __.CSR0821
    | Register.CSR0822 -> __.CSR0822
    | Register.CSR0823 -> __.CSR0823
    | Register.CSR0824 -> __.CSR0824
    | Register.CSR0825 -> __.CSR0825
    | Register.CSR0826 -> __.CSR0826
    | Register.CSR0827 -> __.CSR0827
    | Register.CSR0828 -> __.CSR0828
    | Register.CSR0829 -> __.CSR0829
    | Register.CSR0830 -> __.CSR0830
    | Register.CSR0831 -> __.CSR0831
    | Register.CSR1952 -> __.CSR1952
    | Register.CSR1953 -> __.CSR1953
    | Register.CSR1954 -> __.CSR1954
    | Register.CSR1955 -> __.CSR1955
    | Register.CSR1968 -> __.CSR1968
    | Register.CSR1969 -> __.CSR1969
    | Register.CSR1970 -> __.CSR1970
    | Register.CSR1971 -> __.CSR1971
    | _ -> raise UnhandledRegExprException

// vim: set tw=80 sts=2 sw=2:
