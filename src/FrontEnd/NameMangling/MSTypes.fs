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

namespace B2R2.FrontEnd.NameMangling

/// Indicates the data type in the Enum Type.
type EnumTypeKind =
  | CharEnum
  | UnsignedCharEnum
  | ShortEnum
  | UnsignedShortEnum
  | GeneralEnum
  | UnsignedIntEnum
  | LongEnum
  | UnsignedLongEnum
  | UnknownEnumType

module EnumTypeKind =
  let fromChar = function
    | '0' -> CharEnum
    | '1' -> UnsignedCharEnum
    | '2' -> ShortEnum
    | '3' -> UnsignedShortEnum
    | '4' -> GeneralEnum
    | '5' -> UnsignedIntEnum
    | '6' -> LongEnum
    | '7' -> UnsignedLongEnum
    |  _  -> UnknownEnumType

  let toString = function
    | CharEnum -> " char"
    | UnsignedCharEnum -> " unsigned char"
    | ShortEnum -> " short"
    | UnsignedShortEnum -> " unsigned short"
    | GeneralEnum -> ""
    | UnsignedIntEnum -> " unsigned int"
    | LongEnum -> " long"
    | UnsignedLongEnum -> " unsigned long"
    | UnknownEnumType -> " ???"


/// Indicates the type of the complex type.
type ComplexTypeKind =
  | Union
  | Struct
  | Class
  | Cointerface
  | Coclass
  | UnknownComplexType

module ComplexTypeKind =
  let fromString = function
    | "T"  -> Union
    | "U"  -> Struct
    | "V"  -> Class
    | "Y"  -> Cointerface
    | "_X" -> Coclass
    |  _   -> UnknownComplexType

  let toString = function
    | Union -> "union "
    | Struct -> "struct "
    | Class -> "class "
    | Cointerface -> "cointerface"
    | Coclass -> "coclass"
    | UnknownComplexType -> "???"


/// Indicates the calling convention.
type CallConvention =
  | Cdecl
  | Pascal
  | Thiscall
  | Stdcall
  | Fastcall
  | Clrcall
  | Free
  | UnknownCallConvention

module CallConvention =
  let fromChar = function
    | 'A' | 'B' -> Cdecl
    | 'C' | 'D' -> Pascal
    | 'E' | 'F' -> Thiscall
    | 'G' | 'H' -> Stdcall
    | 'I' | 'J' -> Fastcall
    | 'K' | 'L' -> Free
    | 'M' -> Clrcall
    | _ -> UnknownCallConvention

  let toString = function
    | Cdecl -> "__cdecl"
    | Pascal -> "__pascal"
    | Thiscall -> "__thiscall"
    | Stdcall -> "__stdcall"
    | Fastcall -> "__fastcall"
    | Clrcall -> "__clrcall"
    | Free -> ""
    | UnknownCallConvention-> "???"

/// Indicates the calling scope(access level).
type CallScope =
  | PrivateAccess
  | PrivateStatic
  | PrivateVirtual
  | PrivateThunk
  | Protected
  | ProtectedStatic
  | ProtectedVirtual
  | ProtectedThunk
  | PublicAccess
  | PublicStatic
  | PublicVirtual
  | PublicThunk
  | FreeScope
  | UnknownCallScope

module CallScope =
  let fromChar = function
    | 'A' | 'B' -> PrivateAccess
    | 'C' | 'D' -> PrivateStatic
    | 'E' | 'F' -> PrivateVirtual
    | 'G' | 'H' | '0' | '1' -> PrivateThunk
    | 'I' | 'J' -> Protected
    | 'K' | 'L' -> ProtectedStatic
    | 'M' | 'N' -> ProtectedVirtual
    | 'O' | 'P' | '2' | '3' -> ProtectedThunk
    | 'Q' | 'R' -> PublicAccess
    | 'S' | 'T' -> PublicStatic
    | 'U' | 'V' -> PublicVirtual
    | 'W' | 'X' | '4' | '5' -> PublicThunk
    | 'Y' | 'Z' -> FreeScope
    | _ -> UnknownCallScope


  let toString = function
    | PrivateAccess -> "private: "
    | PrivateStatic -> "private: static "
    | PrivateVirtual -> "private: virtual "
    | PrivateThunk -> "[thunk]:private: virtual "
    | Protected -> "protected: "
    | ProtectedStatic -> "protected: static "
    | ProtectedVirtual -> "protected: virtual "
    | ProtectedThunk -> "[thunk]:protected: virtual "
    | PublicAccess -> "public: "
    | PublicStatic -> "public: static "
    | PublicVirtual -> "public: virtual "
    | PublicThunk -> "[thunk]:public: virtual "
    | FreeScope -> ""
    | UnknownCallScope -> "???"

/// Indicates modifier prefixes for a CV Modifier.
type ModifierPrefix =
  | Ptr64Mod
  | UnalignedMod
  | ReferenceMod
  | DoubleReferenceMod
  | RestrictMod
  | UnknownPrefix

module ModifierPrefix =
  let fromChar = function
    | 'E' -> Ptr64Mod
    | 'F' -> UnalignedMod
    | 'G' -> ReferenceMod
    | 'H' -> DoubleReferenceMod
    | 'I' -> RestrictMod
    |  _  -> UnknownPrefix

/// Indicates CV class modifier.
type CVModifier =
  | NoMod
  | Constant
  | Volatile
  | ConstantVolatile
  | UnknownMod

module CVModifier =
  let fromChar = function
    | 'A' | 'Q' | 'U' | 'Y' | 'M' | '2' -> NoMod
    | 'B' | 'J' | 'R' | 'V' | 'Z' | 'N' |'3'-> Constant
    | 'C' | 'G' | 'K' | 'S' | 'W' | 'O' | '0' | '4' -> Volatile
    | 'D' | 'H' | 'L' | 'T' | 'X' | 'P' | '1' | '5' -> ConstantVolatile
    | _ -> UnknownMod

  let toString = function
    | NoMod -> " "
    | Constant -> " const "
    | Volatile -> " volatile "
    | ConstantVolatile -> " const volatile "
    | UnknownMod -> "???"

/// Indicates the type of the pointer.
type PointerTypeIndicator =
  | NormalPointer
  | VolatilePointer
  | ConstantPointer
  | ConstantVolatilePointer
  | NormalReference
  | VolatileReference
  | NormalRValueReference
  | VolatileRValueReference
  | EmptyPointer
  | UnknownPointer

module PointerTypeIndicator =
  let fromChar = function
    | 'A' -> NormalReference
    | 'B' -> VolatileReference
    | 'C' | 'M' -> EmptyPointer // M for ignored __based pointers.
    | 'P' -> NormalPointer
    | 'Q' -> ConstantPointer
    | 'R' -> VolatilePointer
    | 'S' -> ConstantVolatilePointer
    | 'X' -> NormalRValueReference
    | 'Z' -> VolatileRValueReference
    | _   -> UnknownPointer

  let getPointerType = function
    | NormalPointer | NormalReference | EmptyPointer | NormalRValueReference ->
      ""
    | VolatilePointer | VolatileReference | VolatileRValueReference ->
      " volatile"
    | ConstantPointer -> " const"
    | ConstantVolatilePointer -> " const volatile"
    | UnknownPointer -> "?"

  let getPointerSymbol = function
    | EmptyPointer -> ""
    | NormalReference | VolatileReference -> "&"
    | NormalRValueReference | VolatileRValueReference -> "&&"
    | _ -> "*"

/// Built in types represented by a single letter.
type NormalBuiltInType =
  | EmptyReturn // @ symbol can be used as a return type.
  | SignedChar
  | Char
  | UnsignedChar
  | Short
  | UnsignedShort
  | Int
  | UnsignedInt
  | Long
  | UnsignedLong
  | Float
  | Double
  | LongDouble
  | VoidP
  | Ellipsis
  | UnknownNormalBuiltInType

module NormalBuiltInType =
  let fromChar = function
    | 'C' -> SignedChar
    | 'D' -> Char
    | 'E' -> UnsignedChar
    | 'F' -> Short
    | 'G' -> UnsignedShort
    | 'H' -> Int
    | 'I' -> UnsignedInt
    | 'J' -> Long
    | 'K' -> UnsignedLong
    | 'M' -> Float
    | 'N' -> Double
    | 'O' -> LongDouble
    | 'X' -> VoidP
    | 'Z' -> Ellipsis
    |  _  -> UnknownNormalBuiltInType

  let toString = function
    | EmptyReturn -> ""
    | SignedChar -> "signed char"
    | Char -> "char"
    | UnsignedChar -> "unsigned char"
    | Short -> "short"
    | UnsignedShort -> "unsigned short"
    | Int -> "int"
    | UnsignedInt -> "unsigned int"
    | Long -> "long"
    | UnsignedLong -> "unsigned long"
    | Float -> "float"
    | Double -> "double"
    | LongDouble -> "long double"
    | VoidP -> "void"
    | Ellipsis -> "..."
    | _ -> "???"

/// Built in types that are represented by an underscore (_), then a letter.
type UnderscoredBuiltInType =
  | Int8
  | UnsignedInt8
  | Int16
  | UnsignedInt16
  | Int32
  | UnsignedInt32
  | Int64
  | UnsignedInt64
  | Int128
  | UnsignedInt128
  | Bool
  | Char16T
  | Char32T
  | WCharT
  | UnknownUnderscoredBuiltInType

module UnderscoredBuiltInType =
  let fromChar = function
    | 'D' -> Int8
    | 'E' -> UnsignedInt8
    | 'F' -> Int16
    | 'G' -> UnsignedInt16
    | 'H' -> Int32
    | 'I' -> UnsignedInt32
    | 'J' -> Int64
    | 'K' -> UnsignedInt64
    | 'L' -> Int128
    | 'M' -> UnsignedInt128
    | 'N' -> Bool
    | 'S' -> Char16T
    | 'U' -> Char32T
    | 'W' -> WCharT
    |  _  -> UnknownUnderscoredBuiltInType

  let toString = function
    | Int8 -> "__int8"
    | UnsignedInt8 -> "unsigned __int8"
    | Int16 -> "__int16"
    | UnsignedInt16 -> "unsigned __int16"
    | Int32 -> "__int32"
    | UnsignedInt32 -> "unsigned __int32"
    | Int64 -> "__int64"
    | UnsignedInt64 -> "unsigned __int64"
    | Int128 -> "__int128"
    | UnsignedInt128 -> "unsigned __int128"
    | Bool -> "bool"
    | Char16T -> "char16_t"
    | Char32T -> "char32_t"
    | WCharT -> "wchar_t"
    | UnknownUnderscoredBuiltInType -> "???"

/// Not used while parsing. Only used during interpretation when a function
/// returns a function pointer to accomodate the weird syntax.
type InterpHelperString = string

/// Indicates the dimension(length) of the array.
type ArrayLength = int

/// AST for microsoft mangled expressions.
type MSExpr =
  /// A name without type information.
  | Name of string

  /// A nested name without type information.
  | FullName of MSExpr list

  /// An MSExpr form for a normal builtInType represented by a single letter.
  | SimpleBuiltInType of NormalBuiltInType

  /// An MSExpr form for an underscored builtInType represented by an underscore
  /// first then a single letter.
  | ExtendedBuiltInType of UnderscoredBuiltInType

  /// PointerStrT of PointerType * (prefixes * cvModifier) * cvTypeMSExpr.
  /// The cvTypeMSExpr differentiates between normalPointers, __basedPointers,
  /// memberPointers, or __based member pointers.
  /// Has all the information about the pointer symbol including prefixes.
  | PointerStrT of PointerTypeIndicator
                 * (ModifierPrefix list * CVModifier)
                 * MSExpr

  /// A pointer type of PointerStrType * PointedType.
  | PointerT of MSExpr * MSExpr

  /// Whole information of a complex type of complaexTypeKind * TypeBody.
  | ComplexT of ComplexTypeKind * MSExpr

  /// EnumType of the Enum data type * name.
  | EnumType of EnumTypeKind * MSExpr

  /// For functions as arguements with PointerStrs, calling convention,
  /// return type , carry string, and Parameter types.
  | FuncPointer of pointers : MSExpr list
                 * callingConvention: CallConvention
                 * returnType: MSExpr
                 * interpretationHelperString: InterpHelperString
                 * parameterTypes: MSExpr list
                 * modifiers: (ModifierPrefix list * CVModifier) option

  /// A function of scope * modifiers * calling convention * Name
  /// * ReturnType * ParameterTypes * ReturnType modifiers (if any).
  | FunctionT of callScope: CallScope
               * modifiers: (ModifierPrefix list * CVModifier)
               * callingConvention: CallConvention
               * functionName: MSExpr
               * returnType: MSExpr
               * parameterTypes: MSExpr list
               * returnTypeModifier: (ModifierPrefix list * CVModifier) option

  /// A template of FullName * Arguement types.
  | Template of MSExpr * MSExpr list

  /// A constructor of Name.
  | Constructor of MSExpr

  /// A destructor of Name.
  | Destructor of MSExpr

  /// RTTI0 code of any type.
  | RTTI0 of MSExpr

  /// Function nested in another function.
  | NestedFunc of MSExpr

  /// Mangled symbol pointer that comes only as template parameter.
  | MangledSymbolPtr of MSExpr

  /// Constructor comming inside templates.
  | ConstructedTemplate of MSExpr list * MSExpr

  /// Modified type of type * modifiers.
  | ModifiedType of MSExpr * (ModifierPrefix list * CVModifier)

  /// Value of name * type.
  | ValueT of MSExpr * MSExpr

  /// Pointer to an array of pointerStrTs * dimensions * Array data type.
  | ArrayPtr of MSExpr list * ArrayLength list * MSExpr

  /// Array type (not pointer to array) of modified data type * dimension.
  | ArrayType of MSExpr * ArrayLength

  /// Thunk Function type of calling Type * Name Component * Type Component
  /// * Return Type
  | ThunkF of CallConvention * MSExpr * MSExpr * MSExpr

  /// Ingored type for temlates.
  | IgnoredType

  /// Concatinate Type of MSExpr list.
  /// Concatinates the demangled string of each MSExpr in the list.
  | ConcatT of MSExpr list


/// Userstate to handle name and type substitutions.
type MSUserState = {
  NameList: MSExpr list
  TypeList: MSExpr list
}
with
  static member Default = { NameList = []; TypeList = [] }

type MSParser<'a> = FParsec.Primitives.Parser<'a, MSUserState>
