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

/// Represents a factory for accessing various RISCV64 register variables.
type RegisterFactory(wordSize) =
  let rt = WordSize.toRegType wordSize
  let fflags = AST.var 32<rt> (Register.toRegID Register.FFLAGS) "FFLAGS"
  let frm = AST.var 32<rt> (Register.toRegID Register.FRM) "FRM"

  let x0 = AST.var rt (Register.toRegID Register.X0) "X0"
  let x1 = AST.var rt (Register.toRegID Register.X1) "X1"
  let x2 = AST.var rt (Register.toRegID Register.X2) "X2"
  let x3 = AST.var rt (Register.toRegID Register.X3) "X3"
  let x4 = AST.var rt (Register.toRegID Register.X4) "X4"
  let x5 = AST.var rt (Register.toRegID Register.X5) "X5"
  let x6 = AST.var rt (Register.toRegID Register.X6) "X6"
  let x7 = AST.var rt (Register.toRegID Register.X7) "X7"
  let x8 = AST.var rt (Register.toRegID Register.X8) "X8"
  let x9 = AST.var rt (Register.toRegID Register.X9) "X9"
  let x10 = AST.var rt (Register.toRegID Register.X10) "X10"
  let x11 = AST.var rt (Register.toRegID Register.X11) "X11"
  let x12 = AST.var rt (Register.toRegID Register.X12) "X12"
  let x13 = AST.var rt (Register.toRegID Register.X13) "X13"
  let x14 = AST.var rt (Register.toRegID Register.X14) "X14"
  let x15 = AST.var rt (Register.toRegID Register.X15) "X15"
  let x16 = AST.var rt (Register.toRegID Register.X16) "X16"
  let x17 = AST.var rt (Register.toRegID Register.X17) "X17"
  let x18 = AST.var rt (Register.toRegID Register.X18) "X18"
  let x19 = AST.var rt (Register.toRegID Register.X19) "X19"
  let x20 = AST.var rt (Register.toRegID Register.X20) "X20"
  let x21 = AST.var rt (Register.toRegID Register.X21) "X21"
  let x22 = AST.var rt (Register.toRegID Register.X22) "X22"
  let x23 = AST.var rt (Register.toRegID Register.X23) "X23"
  let x24 = AST.var rt (Register.toRegID Register.X24) "X24"
  let x25 = AST.var rt (Register.toRegID Register.X25) "X25"
  let x26 = AST.var rt (Register.toRegID Register.X26) "X26"
  let x27 = AST.var rt (Register.toRegID Register.X27) "X27"
  let x28 = AST.var rt (Register.toRegID Register.X28) "X28"
  let x29 = AST.var rt (Register.toRegID Register.X29) "X29"
  let x30 = AST.var rt (Register.toRegID Register.X30) "X30"
  let x31 = AST.var rt (Register.toRegID Register.X31) "X31"

  let f0 = AST.var rt (Register.toRegID Register.F0) "F0"
  let f1 = AST.var rt (Register.toRegID Register.F1) "F1"
  let f2 = AST.var rt (Register.toRegID Register.F2) "F2"
  let f3 = AST.var rt (Register.toRegID Register.F3) "F3"
  let f4 = AST.var rt (Register.toRegID Register.F4) "F4"
  let f5 = AST.var rt (Register.toRegID Register.F5) "F5"
  let f6 = AST.var rt (Register.toRegID Register.F6) "F6"
  let f7 = AST.var rt (Register.toRegID Register.F7) "F7"
  let f8 = AST.var rt (Register.toRegID Register.F8) "F8"
  let f9 = AST.var rt (Register.toRegID Register.F9) "F9"
  let f10 = AST.var rt (Register.toRegID Register.F10) "F10"
  let f11 = AST.var rt (Register.toRegID Register.F11) "F11"
  let f12 = AST.var rt (Register.toRegID Register.F12) "F12"
  let f13 = AST.var rt (Register.toRegID Register.F13) "F13"
  let f14 = AST.var rt (Register.toRegID Register.F14) "F14"
  let f15 = AST.var rt (Register.toRegID Register.F15) "F15"
  let f16 = AST.var rt (Register.toRegID Register.F16) "F16"
  let f17 = AST.var rt (Register.toRegID Register.F17) "F17"
  let f18 = AST.var rt (Register.toRegID Register.F18) "F18"
  let f19 = AST.var rt (Register.toRegID Register.F19) "F19"
  let f20 = AST.var rt (Register.toRegID Register.F20) "F20"
  let f21 = AST.var rt (Register.toRegID Register.F21) "F21"
  let f22 = AST.var rt (Register.toRegID Register.F22) "F22"
  let f23 = AST.var rt (Register.toRegID Register.F23) "F23"
  let f24 = AST.var rt (Register.toRegID Register.F24) "F24"
  let f25 = AST.var rt (Register.toRegID Register.F25) "F25"
  let f26 = AST.var rt (Register.toRegID Register.F26) "F26"
  let f27 = AST.var rt (Register.toRegID Register.F27) "F27"
  let f28 = AST.var rt (Register.toRegID Register.F28) "F28"
  let f29 = AST.var rt (Register.toRegID Register.F29) "F29"
  let f30 = AST.var rt (Register.toRegID Register.F30) "F30"
  let f31 = AST.var rt (Register.toRegID Register.F31) "F31"

  let pc = AST.pcvar rt "PC"
  let rc = AST.var 1<rt> (Register.toRegID Register.RC) "RC"
  let fcsr =
    AST.``or`` (AST.``and`` fflags (numI32 0b11111 32<rt>))
               (AST.shl (AST.``and`` frm (numI32 0b111 32<rt>))
                        (numI32 5 32<rt>))

  let csr0768 = AST.var rt (Register.toRegID Register.CSR0768) "CSR0768"
  let csr0769 = AST.var rt (Register.toRegID Register.CSR0769) "CSR0769"
  let csr0770 = AST.var rt (Register.toRegID Register.CSR0770) "CSR0770"
  let csr0771 = AST.var rt (Register.toRegID Register.CSR0771) "CSR0771"
  let csr0772 = AST.var rt (Register.toRegID Register.CSR0772) "CSR0772"
  let csr0773 = AST.var rt (Register.toRegID Register.CSR0773) "CSR0773"
  let csr0784 = AST.var rt (Register.toRegID Register.CSR0784) "CSR0784"
  let csr0832 = AST.var rt (Register.toRegID Register.CSR0832) "CSR0832"
  let csr0833 = AST.var rt (Register.toRegID Register.CSR0833) "CSR0833"
  let csr0834 = AST.var rt (Register.toRegID Register.CSR0834) "CSR0834"
  let csr0835 = AST.var rt (Register.toRegID Register.CSR0835) "CSR0835"
  let csr0836 = AST.var rt (Register.toRegID Register.CSR0836) "CSR0836"
  let csr0842 = AST.var rt (Register.toRegID Register.CSR0842) "CSR0842"
  let csr0843 = AST.var rt (Register.toRegID Register.CSR0843) "CSR0843"
  let csr3114 = AST.var rt (Register.toRegID Register.CSR3114) "CSR3114"
  let csr3787 = AST.var rt (Register.toRegID Register.CSR3787) "CSR3787"
  let csr3857 = AST.var rt (Register.toRegID Register.CSR3857) "CSR3857"
  let csr3858 = AST.var rt (Register.toRegID Register.CSR3858) "CSR3858"
  let csr3859 = AST.var rt (Register.toRegID Register.CSR3859) "CSR3859"
  let csr3860 = AST.var rt (Register.toRegID Register.CSR3860) "CSR3860"
  let csr0928 = AST.var rt (Register.toRegID Register.CSR0928) "CSR0928"
  let csr0930 = AST.var rt (Register.toRegID Register.CSR0930) "CSR0930"
  let csr0932 = AST.var rt (Register.toRegID Register.CSR0932) "CSR0932"
  let csr0934 = AST.var rt (Register.toRegID Register.CSR0934) "CSR0934"
  let csr0936 = AST.var rt (Register.toRegID Register.CSR0936) "CSR0936"
  let csr0938 = AST.var rt (Register.toRegID Register.CSR0938) "CSR0938"
  let csr0940 = AST.var rt (Register.toRegID Register.CSR0940) "CSR0940"
  let csr0942 = AST.var rt (Register.toRegID Register.CSR0942) "CSR0942"
  let csr0944 = AST.var rt (Register.toRegID Register.CSR0944) "CSR0944"
  let csr0945 = AST.var rt (Register.toRegID Register.CSR0945) "CSR0945"
  let csr0946 = AST.var rt (Register.toRegID Register.CSR0946) "CSR0946"
  let csr0947 = AST.var rt (Register.toRegID Register.CSR0947) "CSR0947"
  let csr0948 = AST.var rt (Register.toRegID Register.CSR0948) "CSR0948"
  let csr0949 = AST.var rt (Register.toRegID Register.CSR0949) "CSR0949"
  let csr0950 = AST.var rt (Register.toRegID Register.CSR0950) "CSR0950"
  let csr0951 = AST.var rt (Register.toRegID Register.CSR0951) "CSR0951"
  let csr0952 = AST.var rt (Register.toRegID Register.CSR0952) "CSR0952"
  let csr0953 = AST.var rt (Register.toRegID Register.CSR0953) "CSR0953"
  let csr0954 = AST.var rt (Register.toRegID Register.CSR0954) "CSR0954"
  let csr0955 = AST.var rt (Register.toRegID Register.CSR0955) "CSR0955"
  let csr0956 = AST.var rt (Register.toRegID Register.CSR0956) "CSR0956"
  let csr0957 = AST.var rt (Register.toRegID Register.CSR0957) "CSR0957"
  let csr0958 = AST.var rt (Register.toRegID Register.CSR0958) "CSR0958"
  let csr0959 = AST.var rt (Register.toRegID Register.CSR0959) "CSR0959"
  let csr0960 = AST.var rt (Register.toRegID Register.CSR0960) "CSR0960"
  let csr0961 = AST.var rt (Register.toRegID Register.CSR0961) "CSR0961"
  let csr0962 = AST.var rt (Register.toRegID Register.CSR0962) "CSR0962"
  let csr0963 = AST.var rt (Register.toRegID Register.CSR0963) "CSR0963"
  let csr0964 = AST.var rt (Register.toRegID Register.CSR0964) "CSR0964"
  let csr0965 = AST.var rt (Register.toRegID Register.CSR0965) "CSR0965"
  let csr0966 = AST.var rt (Register.toRegID Register.CSR0966) "CSR0966"
  let csr0967 = AST.var rt (Register.toRegID Register.CSR0967) "CSR0967"
  let csr0968 = AST.var rt (Register.toRegID Register.CSR0968) "CSR0968"
  let csr0969 = AST.var rt (Register.toRegID Register.CSR0969) "CSR0969"
  let csr0970 = AST.var rt (Register.toRegID Register.CSR0970) "CSR0970"
  let csr0971 = AST.var rt (Register.toRegID Register.CSR0971) "CSR0971"
  let csr0972 = AST.var rt (Register.toRegID Register.CSR0972) "CSR0972"
  let csr0973 = AST.var rt (Register.toRegID Register.CSR0973) "CSR0973"
  let csr0974 = AST.var rt (Register.toRegID Register.CSR0974) "CSR0974"
  let csr0975 = AST.var rt (Register.toRegID Register.CSR0975) "CSR0975"
  let csr0976 = AST.var rt (Register.toRegID Register.CSR0976) "CSR0976"
  let csr0977 = AST.var rt (Register.toRegID Register.CSR0977) "CSR0977"
  let csr0978 = AST.var rt (Register.toRegID Register.CSR0978) "CSR0978"
  let csr0979 = AST.var rt (Register.toRegID Register.CSR0979) "CSR0979"
  let csr0980 = AST.var rt (Register.toRegID Register.CSR0980) "CSR0980"
  let csr0981 = AST.var rt (Register.toRegID Register.CSR0981) "CSR0981"
  let csr0982 = AST.var rt (Register.toRegID Register.CSR0982) "CSR0982"
  let csr0983 = AST.var rt (Register.toRegID Register.CSR0983) "CSR0983"
  let csr0984 = AST.var rt (Register.toRegID Register.CSR0984) "CSR0984"
  let csr0985 = AST.var rt (Register.toRegID Register.CSR0985) "CSR0985"
  let csr0986 = AST.var rt (Register.toRegID Register.CSR0986) "CSR0986"
  let csr0987 = AST.var rt (Register.toRegID Register.CSR0987) "CSR0987"
  let csr0988 = AST.var rt (Register.toRegID Register.CSR0988) "CSR0988"
  let csr0989 = AST.var rt (Register.toRegID Register.CSR0989) "CSR0989"
  let csr0990 = AST.var rt (Register.toRegID Register.CSR0990) "CSR0990"
  let csr0991 = AST.var rt (Register.toRegID Register.CSR0991) "CSR0991"
  let csr0992 = AST.var rt (Register.toRegID Register.CSR0992) "CSR0992"
  let csr0993 = AST.var rt (Register.toRegID Register.CSR0993) "CSR0993"
  let csr0994 = AST.var rt (Register.toRegID Register.CSR0994) "CSR0994"
  let csr0995 = AST.var rt (Register.toRegID Register.CSR0995) "CSR0995"
  let csr0996 = AST.var rt (Register.toRegID Register.CSR0996) "CSR0996"
  let csr0997 = AST.var rt (Register.toRegID Register.CSR0997) "CSR0997"
  let csr0998 = AST.var rt (Register.toRegID Register.CSR0998) "CSR0998"
  let csr0999 = AST.var rt (Register.toRegID Register.CSR0999) "CSR0999"
  let csr1000 = AST.var rt (Register.toRegID Register.CSR1000) "CSR1000"
  let csr1001 = AST.var rt (Register.toRegID Register.CSR1001) "CSR1001"
  let csr1002 = AST.var rt (Register.toRegID Register.CSR1002) "CSR1002"
  let csr1003 = AST.var rt (Register.toRegID Register.CSR1003) "CSR1003"
  let csr1004 = AST.var rt (Register.toRegID Register.CSR1004) "CSR1004"
  let csr1005 = AST.var rt (Register.toRegID Register.CSR1005) "CSR1005"
  let csr1006 = AST.var rt (Register.toRegID Register.CSR1006) "CSR1006"
  let csr1007 = AST.var rt (Register.toRegID Register.CSR1007) "CSR1007"
  let csr2145 = AST.var rt (Register.toRegID Register.CSR2145) "CSR2145"
  let csr2617 = AST.var rt (Register.toRegID Register.CSR2617) "CSR2617"
  let csr2816 = AST.var rt (Register.toRegID Register.CSR2816) "CSR2816"
  let csr2818 = AST.var rt (Register.toRegID Register.CSR2818) "CSR2818"
  let csr2819 = AST.var rt (Register.toRegID Register.CSR2819) "CSR2819"
  let csr2820 = AST.var rt (Register.toRegID Register.CSR2820) "CSR2820"
  let csr2821 = AST.var rt (Register.toRegID Register.CSR2821) "CSR2821"
  let csr2822 = AST.var rt (Register.toRegID Register.CSR2822) "CSR2822"
  let csr2823 = AST.var rt (Register.toRegID Register.CSR2823) "CSR2823"
  let csr2824 = AST.var rt (Register.toRegID Register.CSR2824) "CSR2824"
  let csr2825 = AST.var rt (Register.toRegID Register.CSR2825) "CSR2825"
  let csr2826 = AST.var rt (Register.toRegID Register.CSR2826) "CSR2826"
  let csr2827 = AST.var rt (Register.toRegID Register.CSR2827) "CSR2827"
  let csr2828 = AST.var rt (Register.toRegID Register.CSR2828) "CSR2828"
  let csr2829 = AST.var rt (Register.toRegID Register.CSR2829) "CSR2829"
  let csr2830 = AST.var rt (Register.toRegID Register.CSR2830) "CSR2830"
  let csr2831 = AST.var rt (Register.toRegID Register.CSR2831) "CSR2831"
  let csr2832 = AST.var rt (Register.toRegID Register.CSR2832) "CSR2832"
  let csr2833 = AST.var rt (Register.toRegID Register.CSR2833) "CSR2833"
  let csr2834 = AST.var rt (Register.toRegID Register.CSR2834) "CSR2834"
  let csr2835 = AST.var rt (Register.toRegID Register.CSR2835) "CSR2835"
  let csr2836 = AST.var rt (Register.toRegID Register.CSR2836) "CSR2836"
  let csr2837 = AST.var rt (Register.toRegID Register.CSR2837) "CSR2837"
  let csr2838 = AST.var rt (Register.toRegID Register.CSR2838) "CSR2838"
  let csr2839 = AST.var rt (Register.toRegID Register.CSR2839) "CSR2839"
  let csr2840 = AST.var rt (Register.toRegID Register.CSR2840) "CSR2840"
  let csr2841 = AST.var rt (Register.toRegID Register.CSR2841) "CSR2841"
  let csr2842 = AST.var rt (Register.toRegID Register.CSR2842) "CSR2842"
  let csr2843 = AST.var rt (Register.toRegID Register.CSR2843) "CSR2843"
  let csr2844 = AST.var rt (Register.toRegID Register.CSR2844) "CSR2844"
  let csr2845 = AST.var rt (Register.toRegID Register.CSR2845) "CSR2845"
  let csr2846 = AST.var rt (Register.toRegID Register.CSR2846) "CSR2846"
  let csr2847 = AST.var rt (Register.toRegID Register.CSR2847) "CSR2847"
  let csr2945 = AST.var rt (Register.toRegID Register.CSR2945) "CSR2945"
  let csr0800 = AST.var rt (Register.toRegID Register.CSR0800) "CSR0800"
  let csr0803 = AST.var rt (Register.toRegID Register.CSR0803) "CSR0803"
  let csr0804 = AST.var rt (Register.toRegID Register.CSR0804) "CSR0804"
  let csr0805 = AST.var rt (Register.toRegID Register.CSR0805) "CSR0805"
  let csr0806 = AST.var rt (Register.toRegID Register.CSR0806) "CSR0806"
  let csr0807 = AST.var rt (Register.toRegID Register.CSR0807) "CSR0807"
  let csr0808 = AST.var rt (Register.toRegID Register.CSR0808) "CSR0808"
  let csr0809 = AST.var rt (Register.toRegID Register.CSR0809) "CSR0809"
  let csr0810 = AST.var rt (Register.toRegID Register.CSR0810) "CSR0810"
  let csr0811 = AST.var rt (Register.toRegID Register.CSR0811) "CSR0811"
  let csr0812 = AST.var rt (Register.toRegID Register.CSR0812) "CSR0812"
  let csr0813 = AST.var rt (Register.toRegID Register.CSR0813) "CSR0813"
  let csr0814 = AST.var rt (Register.toRegID Register.CSR0814) "CSR0814"
  let csr0815 = AST.var rt (Register.toRegID Register.CSR0815) "CSR0815"
  let csr0816 = AST.var rt (Register.toRegID Register.CSR0816) "CSR0816"
  let csr0817 = AST.var rt (Register.toRegID Register.CSR0817) "CSR0817"
  let csr0818 = AST.var rt (Register.toRegID Register.CSR0818) "CSR0818"
  let csr0819 = AST.var rt (Register.toRegID Register.CSR0819) "CSR0819"
  let csr0820 = AST.var rt (Register.toRegID Register.CSR0820) "CSR0820"
  let csr0821 = AST.var rt (Register.toRegID Register.CSR0821) "CSR0821"
  let csr0822 = AST.var rt (Register.toRegID Register.CSR0822) "CSR0822"
  let csr0823 = AST.var rt (Register.toRegID Register.CSR0823) "CSR0823"
  let csr0824 = AST.var rt (Register.toRegID Register.CSR0824) "CSR0824"
  let csr0825 = AST.var rt (Register.toRegID Register.CSR0825) "CSR0825"
  let csr0826 = AST.var rt (Register.toRegID Register.CSR0826) "CSR0826"
  let csr0827 = AST.var rt (Register.toRegID Register.CSR0827) "CSR0827"
  let csr0828 = AST.var rt (Register.toRegID Register.CSR0828) "CSR0828"
  let csr0829 = AST.var rt (Register.toRegID Register.CSR0829) "CSR0829"
  let csr0830 = AST.var rt (Register.toRegID Register.CSR0830) "CSR0830"
  let csr0831 = AST.var rt (Register.toRegID Register.CSR0831) "CSR0831"
  let csr1952 = AST.var rt (Register.toRegID Register.CSR1952) "CSR1952"
  let csr1953 = AST.var rt (Register.toRegID Register.CSR1953) "CSR1953"
  let csr1954 = AST.var rt (Register.toRegID Register.CSR1954) "CSR1954"
  let csr1955 = AST.var rt (Register.toRegID Register.CSR1955) "CSR1955"
  let csr1968 = AST.var rt (Register.toRegID Register.CSR1968) "CSR1968"
  let csr1969 = AST.var rt (Register.toRegID Register.CSR1969) "CSR1969"
  let csr1970 = AST.var rt (Register.toRegID Register.CSR1970) "CSR1970"
  let csr1971 = AST.var rt (Register.toRegID Register.CSR1971) "CSR1971"

  interface IRegisterFactory with
    member _.GetRegVar rid =
      match Register.ofRegID rid with
      | Register.PC  -> pc
      | Register.RC -> rc
      | Register.X0 -> x0
      | Register.X1 -> x1
      | Register.X2 -> x2
      | Register.X3 -> x3
      | Register.X4 -> x4
      | Register.X5 -> x5
      | Register.X6 -> x6
      | Register.X7 -> x7
      | Register.X8 -> x8
      | Register.X9 -> x9
      | Register.X10 -> x10
      | Register.X11 -> x11
      | Register.X12 -> x12
      | Register.X13 -> x13
      | Register.X14 -> x14
      | Register.X15 -> x15
      | Register.X16 -> x16
      | Register.X17 -> x17
      | Register.X18 -> x18
      | Register.X19 -> x19
      | Register.X20 -> x20
      | Register.X21 -> x21
      | Register.X22 -> x22
      | Register.X23 -> x23
      | Register.X24 -> x24
      | Register.X25 -> x25
      | Register.X26 -> x26
      | Register.X27 -> x27
      | Register.X28 -> x28
      | Register.X29 -> x29
      | Register.X30 -> x30
      | Register.X31 -> x31
      | Register.F0 -> f0
      | Register.F1 -> f1
      | Register.F2 -> f2
      | Register.F3 -> f3
      | Register.F4 -> f4
      | Register.F5 -> f5
      | Register.F6 -> f6
      | Register.F7 -> f7
      | Register.F8 -> f8
      | Register.F9 -> f9
      | Register.F10 -> f10
      | Register.F11 -> f11
      | Register.F12 -> f12
      | Register.F13 -> f13
      | Register.F14 -> f14
      | Register.F15 -> f15
      | Register.F16 -> f16
      | Register.F17 -> f17
      | Register.F18 -> f18
      | Register.F19 -> f19
      | Register.F20 -> f20
      | Register.F21 -> f21
      | Register.F22 -> f22
      | Register.F23 -> f23
      | Register.F24 -> f24
      | Register.F25 -> f25
      | Register.F26 -> f26
      | Register.F27 -> f27
      | Register.F28 -> f28
      | Register.F29 -> f29
      | Register.F30 -> f30
      | Register.F31 -> f31
      | Register.FFLAGS -> fflags
      | Register.FRM -> frm
      | Register.FCSR -> fcsr
      | Register.CSR0768 -> csr0768
      | Register.CSR0769 -> csr0769
      | Register.CSR0770 -> csr0770
      | Register.CSR0771 -> csr0771
      | Register.CSR0772 -> csr0772
      | Register.CSR0773 -> csr0773
      | Register.CSR0784 -> csr0784
      | Register.CSR0832 -> csr0832
      | Register.CSR0833 -> csr0833
      | Register.CSR0834 -> csr0834
      | Register.CSR0835 -> csr0835
      | Register.CSR0836 -> csr0836
      | Register.CSR0842 -> csr0842
      | Register.CSR0843 -> csr0843
      | Register.CSR3114 -> csr3114
      | Register.CSR3787 -> csr3787
      | Register.CSR3857 -> csr3857
      | Register.CSR3858 -> csr3858
      | Register.CSR3859 -> csr3859
      | Register.CSR3860 -> csr3860
      | Register.CSR0928 -> csr0928
      | Register.CSR0930 -> csr0930
      | Register.CSR0932 -> csr0932
      | Register.CSR0934 -> csr0934
      | Register.CSR0936 -> csr0936
      | Register.CSR0938 -> csr0938
      | Register.CSR0940 -> csr0940
      | Register.CSR0942 -> csr0942
      | Register.CSR0944 -> csr0944
      | Register.CSR0945 -> csr0945
      | Register.CSR0946 -> csr0946
      | Register.CSR0947 -> csr0947
      | Register.CSR0948 -> csr0948
      | Register.CSR0949 -> csr0949
      | Register.CSR0950 -> csr0950
      | Register.CSR0951 -> csr0951
      | Register.CSR0952 -> csr0952
      | Register.CSR0953 -> csr0953
      | Register.CSR0954 -> csr0954
      | Register.CSR0955 -> csr0955
      | Register.CSR0956 -> csr0956
      | Register.CSR0957 -> csr0957
      | Register.CSR0958 -> csr0958
      | Register.CSR0959 -> csr0959
      | Register.CSR0960 -> csr0960
      | Register.CSR0961 -> csr0961
      | Register.CSR0962 -> csr0962
      | Register.CSR0963 -> csr0963
      | Register.CSR0964 -> csr0964
      | Register.CSR0965 -> csr0965
      | Register.CSR0966 -> csr0966
      | Register.CSR0967 -> csr0967
      | Register.CSR0968 -> csr0968
      | Register.CSR0969 -> csr0969
      | Register.CSR0970 -> csr0970
      | Register.CSR0971 -> csr0971
      | Register.CSR0972 -> csr0972
      | Register.CSR0973 -> csr0973
      | Register.CSR0974 -> csr0974
      | Register.CSR0975 -> csr0975
      | Register.CSR0976 -> csr0976
      | Register.CSR0977 -> csr0977
      | Register.CSR0978 -> csr0978
      | Register.CSR0979 -> csr0979
      | Register.CSR0980 -> csr0980
      | Register.CSR0981 -> csr0981
      | Register.CSR0982 -> csr0982
      | Register.CSR0983 -> csr0983
      | Register.CSR0984 -> csr0984
      | Register.CSR0985 -> csr0985
      | Register.CSR0986 -> csr0986
      | Register.CSR0987 -> csr0987
      | Register.CSR0988 -> csr0988
      | Register.CSR0989 -> csr0989
      | Register.CSR0990 -> csr0990
      | Register.CSR0991 -> csr0991
      | Register.CSR0992 -> csr0992
      | Register.CSR0993 -> csr0993
      | Register.CSR0994 -> csr0994
      | Register.CSR0995 -> csr0995
      | Register.CSR0996 -> csr0996
      | Register.CSR0997 -> csr0997
      | Register.CSR0998 -> csr0998
      | Register.CSR0999 -> csr0999
      | Register.CSR1000 -> csr1000
      | Register.CSR1001 -> csr1001
      | Register.CSR1002 -> csr1002
      | Register.CSR1003 -> csr1003
      | Register.CSR1004 -> csr1004
      | Register.CSR1005 -> csr1005
      | Register.CSR1006 -> csr1006
      | Register.CSR1007 -> csr1007
      | Register.CSR2145 -> csr2145
      | Register.CSR2617 -> csr2617
      | Register.CSR2816 -> csr2816
      | Register.CSR2818 -> csr2818
      | Register.CSR2819 -> csr2819
      | Register.CSR2820 -> csr2820
      | Register.CSR2821 -> csr2821
      | Register.CSR2822 -> csr2822
      | Register.CSR2823 -> csr2823
      | Register.CSR2824 -> csr2824
      | Register.CSR2825 -> csr2825
      | Register.CSR2826 -> csr2826
      | Register.CSR2827 -> csr2827
      | Register.CSR2828 -> csr2828
      | Register.CSR2829 -> csr2829
      | Register.CSR2830 -> csr2830
      | Register.CSR2831 -> csr2831
      | Register.CSR2832 -> csr2832
      | Register.CSR2833 -> csr2833
      | Register.CSR2834 -> csr2834
      | Register.CSR2835 -> csr2835
      | Register.CSR2836 -> csr2836
      | Register.CSR2837 -> csr2837
      | Register.CSR2838 -> csr2838
      | Register.CSR2839 -> csr2839
      | Register.CSR2840 -> csr2840
      | Register.CSR2841 -> csr2841
      | Register.CSR2842 -> csr2842
      | Register.CSR2843 -> csr2843
      | Register.CSR2844 -> csr2844
      | Register.CSR2845 -> csr2845
      | Register.CSR2846 -> csr2846
      | Register.CSR2847 -> csr2847
      | Register.CSR2945 -> csr2945
      | Register.CSR0800 -> csr0800
      | Register.CSR0803 -> csr0803
      | Register.CSR0804 -> csr0804
      | Register.CSR0805 -> csr0805
      | Register.CSR0806 -> csr0806
      | Register.CSR0807 -> csr0807
      | Register.CSR0808 -> csr0808
      | Register.CSR0809 -> csr0809
      | Register.CSR0810 -> csr0810
      | Register.CSR0811 -> csr0811
      | Register.CSR0812 -> csr0812
      | Register.CSR0813 -> csr0813
      | Register.CSR0814 -> csr0814
      | Register.CSR0815 -> csr0815
      | Register.CSR0816 -> csr0816
      | Register.CSR0817 -> csr0817
      | Register.CSR0818 -> csr0818
      | Register.CSR0819 -> csr0819
      | Register.CSR0820 -> csr0820
      | Register.CSR0821 -> csr0821
      | Register.CSR0822 -> csr0822
      | Register.CSR0823 -> csr0823
      | Register.CSR0824 -> csr0824
      | Register.CSR0825 -> csr0825
      | Register.CSR0826 -> csr0826
      | Register.CSR0827 -> csr0827
      | Register.CSR0828 -> csr0828
      | Register.CSR0829 -> csr0829
      | Register.CSR0830 -> csr0830
      | Register.CSR0831 -> csr0831
      | Register.CSR1952 -> csr1952
      | Register.CSR1953 -> csr1953
      | Register.CSR1954 -> csr1954
      | Register.CSR1955 -> csr1955
      | Register.CSR1968 -> csr1968
      | Register.CSR1969 -> csr1969
      | Register.CSR1970 -> csr1970
      | Register.CSR1971 -> csr1971
      | _ -> raise InvalidRegisterException

    member _.GetRegVar(name: string) =
      match name.ToLowerInvariant() with
      | "x0" -> x0
      | "x1" -> x1
      | "x2" -> x2
      | "x3" -> x3
      | "x4" -> x4
      | "x5" -> x5
      | "x6" -> x6
      | "x7" -> x7
      | "x8" -> x8
      | "x9" -> x9
      | "x10" -> x10
      | "x11" -> x11
      | "x12" -> x12
      | "x13" -> x13
      | "x14" -> x14
      | "x15" -> x15
      | "x16" -> x16
      | "x17" -> x17
      | "x18" -> x18
      | "x19" -> x19
      | "x20" -> x20
      | "x21" -> x21
      | "x22" -> x22
      | "x23" -> x23
      | "x24" -> x24
      | "x25" -> x25
      | "x26" -> x26
      | "x27" -> x27
      | "x28" -> x28
      | "x29" -> x29
      | "x30" -> x30
      | "x31" -> x31
      | "f0" -> f0
      | "f1" -> f1
      | "f2" -> f2
      | "f3" -> f3
      | "f4" -> f4
      | "f5" -> f5
      | "f6" -> f6
      | "f7" -> f7
      | "f8" -> f8
      | "f9" -> f9
      | "f10" -> f10
      | "f11" -> f11
      | "f12" -> f12
      | "f13" -> f13
      | "f14" -> f14
      | "f15" -> f15
      | "f16" -> f16
      | "f17" -> f17
      | "f18" -> f18
      | "f19" -> f19
      | "f20" -> f20
      | "f21" -> f21
      | "f22" -> f22
      | "f23" -> f23
      | "f24" -> f24
      | "f25" -> f25
      | "f26" -> f26
      | "f27" -> f27
      | "f28" -> f28
      | "f29" -> f29
      | "f30" -> f30
      | "f31" -> f31
      | "pc" -> pc
      | "fcsr" -> fcsr
      | _ -> raise InvalidRegisterException

    member _.GetPseudoRegVar(_id, _idx) = Terminator.impossible ()

    member _.GetAllRegVars() =
      [| x0
         x1
         x2
         x3
         x4
         x5
         x6
         x7
         x8
         x9
         x10
         x11
         x12
         x13
         x14
         x15
         x16
         x17
         x18
         x19
         x20
         x21
         x22
         x23
         x24
         x25
         x26
         x27
         x28
         x29
         x30
         x31
         f0
         f1
         f2
         f3
         f4
         f5
         f6
         f7
         f8
         f9
         f10
         f11
         f12
         f13
         f14
         f15
         f16
         f17
         f18
         f19
         f20
         f21
         f22
         f23
         f24
         f25
         f26
         f27
         f28
         f29
         f30
         f31
         pc
         fcsr |]

    member _.GetGeneralRegVars() =
      [| x0
         x1
         x2
         x3
         x4
         x5
         x6
         x7
         x8
         x9
         x10
         x11
         x12
         x13
         x14
         x15
         x16
         x17
         x18
         x19
         x20
         x21
         x22
         x23
         x24
         x25
         x26
         x27
         x28
         x29
         x30
         x31 |]

    member _.GetRegisterID expr =
      match expr with
      | Var(_, id, _, _) -> id
      | PCVar(_) -> Register.toRegID Register.PC
      | _ -> raise InvalidRegisterException

    member _.GetRegisterID name =
      Register.ofString name |> Register.toRegID

    member _.GetRegisterIDAliases _rid =
      Terminator.futureFeature ()

    member _.GetRegString rid =
      Register.ofRegID rid |> Register.toString

    member this.GetAllRegStrings() =
      let regFactory = this :> IRegisterFactory
      regFactory.GetAllRegVars()
      |> Array.map (regFactory.GetRegisterID >> regFactory.GetRegString)

    member _.GetRegType rid =
      Register.ofRegID rid |> Register.toRegType wordSize

    member _.ProgramCounter =
      Register.PC |> Register.toRegID

    member _.StackPointer =
      Register.X30 |> Register.toRegID |> Some

    member _.FramePointer =
      Register.X29 |> Register.toRegID |> Some

    member _.IsProgramCounter rid =
      Register.toRegID Register.PC = rid

    member _.IsStackPointer rid =
      Register.toRegID Register.X30 = rid

    member _.IsFramePointer rid =
      Register.toRegID Register.X29 = rid
