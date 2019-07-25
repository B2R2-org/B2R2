(*
  B2R2 - the Next-Generation Reversing Platform

  Author: Mehdi Aghakishiyev <agakisiyev.mehdi@gmail.com>
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

module B2R2.NameMangling.ItaniumUtils

open FParsec
open B2R2.NameMangling.ItaniumFunctionPointer

/// Adding Function Pointer to substitution list.
let addfunctionptolist expr =
  updateUserState (fun us -> { us with Namelist = (all expr us.Namelist) })
  >>. preturn expr

/// Adding arguments to substitution list. Seperating qualifiers and pointers
/// for substitution.
let addargumenttolist expr =
  updateUserState
    (fun us ->
    match expr with
    | PointerArg (_, Some (CVqualifier a), a2) ->
      let value = CVqualifier a
      let first = PointerArg ("", Some value, a2)
      let second = expr
      { us with Namelist = second :: first :: us.Namelist }
    | PointerArg (_, Some (RestrictCV (a, None)), a2) ->
      let value1 = Restrict (JustPointer)
      let value2 = RestrictCV (a, None)
      let first = PointerArg ("", Some value1, a2)
      let second = PointerArg ("", Some value2, a2)
      let third = expr
      { us with Namelist = third :: second :: first :: us.Namelist }
    | PointerArg (_, Some (RestrictCV (a, Some b)), a2) ->
      let value1 = RestrictCV (Restrict (Nothing), Some b)
      let value2 =  RestrictCV (Restrict (JustPointer), Some b)
      let value3 = RestrictCV (a, Some b)
      let first = PointerArg ("", Some value1, a2)
      let second = PointerArg ("", Some value2, a2)
      let third = PointerArg ("", Some value3, a2)
      let fourth = expr
      { us with Namelist = fourth :: third :: second :: first :: us.Namelist }
    | BuiltinType (_) -> us
    | RefArg (ReferenceArg (_, Some value), a2) ->
      let first = RefArg (ReferenceArg (Reference Empty, Some value), a2)
      let second = expr
      { us with Namelist = second :: first :: us.Namelist }
    | _ ->
      { us with Namelist = expr :: us.Namelist }
     )
  >>. preturn expr

/// Adding NestedName to substitution list.
let addtoNamelist expr =
  updateUserState
    (fun us ->
      match us.Carry with
      | Dummy _ ->
        { us with
            Namelist = NestedName (None, [expr]) :: us.Namelist
            Carry = NestedName (None, [expr]) }
      | NestedName (a, b) ->
        { us with
            Namelist = NestedName (a,expr :: b) :: us.Namelist
            Carry = NestedName (a,expr :: b) }
      | _ -> us
    )
  >>.preturn expr

/// Updating carry when we reach Sx abrreviation. They are not substituted
/// individually.
let updatecarry c =
  updateUserState
    (fun us ->
      match us.Carry with
      | NestedName (a, b) -> { us with Carry = NestedName (a, c :: b) }
      | _ -> { us with Carry = NestedName (None, [c]) })
  >>. preturn c

/// Function names are not included in substitution. In case of nested names
/// last added unit is removed.
let removelast =
  updateUserState
    (fun us ->
      if List.isEmpty us.Namelist then us
      else { us with Namelist = us.Namelist.Tail })

/// Resetting carry.
let clearCarry =
  updateUserState (fun us -> { us with Carry = Dummy "" })

/// Adding arguments of template into list before the whole template itself.
let saveandreturn p =
  getUserState
  >>= (fun parent ->
        p .>> updateUserState (fun us -> { us with Carry = parent.Carry }))

/// Creating template substitution list consisted of only template arguments.
let checkcarry expr =
  updateUserState
    (fun us ->
      match expr with
      | Template (_name, Arguments b) ->
        { us with TemplateArgList = (List.distinct b) }
      | NestedName (_, b) ->
        let len = List.length b
        match b.[len - 1] with
        | Template (_name, Arguments b) ->
          { us with TemplateArgList = (List.distinct b) }
        | _ -> us
      | _ -> us
    )
  >>. preturn expr

/// Adding single template to the substitution list.
let addTemplate expr =
  updateUserState
    (fun us ->
      match expr with
      | Template (_, _) -> { us with Namelist = expr :: us.Namelist }
      | _ -> us
  )
  >>. preturn expr

/// Template substitution can be substituted by general substitution.
let addTsubtolist expr =
  updateUserState (fun us -> { us with Namelist = expr :: us.Namelist })
  >>. preturn expr
