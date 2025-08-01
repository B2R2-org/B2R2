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

module internal B2R2.FrontEnd.NameMangling.ItaniumUtils

open FParsec
open B2R2.FrontEnd.NameMangling.ItaniumFunctionPointer

/// Adding Function Pointer to substitution list.
let addfunctionptolist expr =
  updateUserState (fun us -> { us with Namelist = (all expr us.Namelist) })
  >>. preturn expr

/// Adding arguments to substitution list. Seperating qualifiers and pointers
/// for substitution.
let addargumenttolist expr =
  updateUserState (fun us ->
    match expr with
    | PointerArg(v, Some value, TemplateSub(a, b)) ->
      let first = PointerArg("", Some value, Specific b)
      let second = PointerArg(v, Some value, Specific b)
      { us with Namelist = second :: first :: us.Namelist }
    | PointerArg(_, Some value, a2) ->
      let first = PointerArg("", Some value, a2)
      let second = expr
      { us with Namelist = second :: first :: us.Namelist }
    | BuiltinType(_) -> us
    | RefArg(ReferenceArg(v, Some value), TemplateSub(a, b)) ->
      let first =
        RefArg(ReferenceArg(Reference Empty, Some value), Specific b)
      let second = RefArg(ReferenceArg(v, Some value), Specific b)
      { us with Namelist = second :: first :: us.Namelist }
    | RefArg(ReferenceArg(_, Some value), a2) ->
      let first = RefArg(ReferenceArg(Reference Empty, Some value), a2)
      let second = expr
      { us with Namelist = second :: first :: us.Namelist }
    | Functionarg(None, _) ->
      us
    | _ ->
      { us with Namelist = expr :: us.Namelist })
  >>. preturn expr

let addLambda expr =
  updateUserState (fun us -> { us with Namelist = expr :: us.Namelist })
  >>. preturn expr

/// Adding NestedName to substitution list.
let addtoNamelist expr =
  updateUserState (fun us ->
    match us.Carry with
    | Dummy _ ->
      { us with
          Namelist = NestedName(Name "", [ expr ]) :: us.Namelist
          Carry = NestedName(Name "", [ expr ]) }
    | NestedName(a, b) ->
      { us with
          Namelist = NestedName(a, expr :: b) :: us.Namelist
          Carry = NestedName(a, expr :: b) }
    | _ -> us)
  >>. preturn expr

/// Updating carry when we reach Sx abrreviation. They are not substituted
/// individually.
let updatecarry c =
  updateUserState (fun us ->
    match us.Carry with
    | NestedName(a, b) -> { us with Carry = NestedName(a, c :: b) }
    | _ -> { us with Carry = NestedName(Name "", [ c ]) })
  >>. preturn c

/// Function names are not included in substitution. In case of nested names
/// last added unit is removed.
let removelast =
  updateUserState (fun us ->
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
  updateUserState (fun us ->
    match expr with
    | Template(_name, Arguments b) ->
      { us with TemplateArgList = b }
    | NestedName(_, b) ->
      let len = List.length b
      match b[len - 1] with
      | Template(_name, Arguments b) ->
        { us with TemplateArgList = b }
      | _ -> us
    | _ -> us)
  >>. preturn expr

/// Adding single template to the substitution list.
let addTemplate expr =
  updateUserState (fun us ->
    match expr with
    | Template _ -> { us with Namelist = expr :: us.Namelist }
    | _ -> us)
  >>. preturn expr

/// Template substitution can be substituted by general substitution.
let addTsubtolist expr =
  updateUserState (fun us ->
    match expr with
    | TemplateSub(a, b) -> { us with Namelist = Specific b :: us.Namelist }
    | _ -> us)
  >>. preturn expr

/// Functions for managing RetFlag. This flag is used to determine whether
/// mangling includes return value or not.
let flagOn =
  updateUserState (fun us -> { us with RetFlag = 1 })

let flagOff =
  updateUserState (fun us -> { us with RetFlag = 0 })

/// Parsing return with respect to flag.
let newsaveandreturn p =
  getUserState >>= (fun us -> if us.RetFlag = 1 then p else (preturn (Name "")))

/// If template name is formed from constructor or destructor then return is not
/// included.
let checkBeginning (a, b) =
  updateUserState (fun us ->
    match a with
    | ConsOrDes _ -> { us with RetFlag = 0 }
    | _ -> { us with RetFlag = 1 })
  >>. preturn (a, b)

/// Adding every element in the pack to substitution list.
let rec addtoList refer alist res =
  match alist with
  | [] -> List.rev res
  | head :: tail ->
    addtoList refer tail (RefArg(refer, head) :: res)

 /// Adding arguments pack to substitution list.
let addArgPack expr =
  updateUserState (fun us ->
    match expr with
    | RefArg(_, Arguments alist) | RefArg(_, TemplateSub(Arguments alist, _)) ->
      if alist <> [] then
        let add = alist[alist.Length - 1]
        { us with Namelist = add :: us.Namelist }
      else
        { us with Namelist = Name "" :: us.Namelist }
    | _ -> us)
  >>. preturn expr

/// When there is reference qualifier, pack is added one more as whole.
let addOnCondition expr =
  updateUserState (fun us ->
    match expr with
    | RefArg(ReferenceArg(Reference Empty, None), b) ->
      { us with Namelist = b :: us.Namelist }
    | RefArg(a, Arguments b) | RefArg(a, TemplateSub(Arguments b, _)) ->
      if b <> [] then
        let add = RefArg(a, b[b.Length - 1])
        let newAdd = Arguments(addtoList a b [])
        { us with Namelist = newAdd :: add :: us.Namelist }
      else
        { us with Namelist = Arguments b :: Name "" :: us.Namelist }
    | _ -> us)
  >>. preturn expr

let addArrayPointer expr =
  updateUserState (fun us ->
    match expr with
    | ArrayPointer(Some _ , a, b) ->
      { us with Namelist = expr :: ArrayPointer(None, a, b) :: us.Namelist }
    | _ -> { us with Namelist = expr :: us.Namelist })
  >>. preturn expr

let argPackFlagOn = updateUserState (fun us -> { us with ArgPackFlag = 1 })

let argPackFlagOff = updateUserState (fun us -> { us with ArgPackFlag = 0 })

/// If argument of template is argument pack it is expanded into seperate
/// templates each containing one argument from pack.
let rec createTemplates name arglist res =
  match arglist with
  | [] -> List.rev res
  | hd :: tail ->
    let add = Template(name, Arguments [ hd ])
    createTemplates name tail (add :: res)

let expandArgs expr =
  getUserState
  >>= (fun us ->
         if us.ArgPackFlag = 1 then
           match expr with
           | Template(a, Arguments [ TemplateSub(args, _) ]) ->
             match args with
             | Arguments arglist ->
               let newlist = createTemplates a arglist []
               preturn (Arguments newlist)
             | _ -> preturn expr
           | _ -> preturn expr
         else
           preturn expr
      )

let rec createCLexprs data arglist res =
  match arglist with
  | [] -> List.rev res
  | hd :: tail ->
    let newarg = hd :: data
    let newExpr = (CallExpr newarg)
    createCLexprs data tail (newExpr :: res)

/// If arguments of expression is list of arguments, meaning pack expansion,
/// seperate expressions each with one argument from list is created.
let expandCL expr =
  match expr with
  | CallExpr a ->
    match a[0] with
    | Arguments arglist ->
      Arguments(createCLexprs a.Tail arglist []) |> preturn
    | _ -> preturn expr
  | _ -> preturn expr

let rec createDTexprs data arglist res =
  match arglist with
  | [] -> List.rev res
  | hd :: tail ->
    let newExpr = DotExpr(hd, data)
    createDTexprs data tail (newExpr :: res)

let expandDT expr =
  match expr with
  | DotExpr(a, b) ->
    match a with
    | Arguments arglist ->
      Arguments(createDTexprs b arglist []) |> preturn
    | _ -> preturn expr
  | _ -> preturn expr
