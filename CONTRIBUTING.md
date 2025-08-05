# Contributing to B2R2

Thank you for taking your time to contribute to B2R2! :+1: Please read this
guideline before creating a PR (Pull Request) or an issue.

### Git Commit Messages

We follow the convention described in [this article](https://chris.beams.io/posts/git-commit/).

- Split the subject line and the body (if needed).
- Start the subject line with a capital letter.
- Do not use a period at the end of the subject line.
- The body is optional: subject-only commit is okay.
- The body should explain *why* you made this commit.
- The subject line is limited to maximum 50 characters.
- Each line in the body is limited to maximum 72 characters.

In addition to the above rules, we prepend a tag to the subject line. A tag is
basically a word within a pair of square brackets. For example, you may consider
using the following tags:

- [Intel]: when the commit is about Intel module.
- [ARMv7]: when the commit is about ARMv7 module.
- [ARMv8]: when the commit is about ARMv8 module.
- [MIPS]: when the commit is about MIPS module.
- [Build]: when the commit is about the build system.
- [IR]: when the commit is about the IR.
- [WebUI]: when the commit is about the WebUI.
- [ELF]: when the commit is about the ELF binaries.
- [PE]: when the commit is about the PE binaries.
- [Mach]: when the commit is about the Mach binaries.
- [Doc]: when the commit is about documentation.
- [CI]: when the commit is about continuous integration.
- [Test]: when the commit is about our unittest modules.

### F# Coding Style

Please read the [F# code formatting guideline](https://docs.microsoft.com/en-us/dotnet/fsharp/style-guide/formatting),
before you proceed as we mostly follow it.

#### Basic Rules

- **Width = 80**: We strictly limit the code width to be *80*.
- **No tabs**: We do *not* use `tab` for spacing.
- **Indentation = 2**: We always use two space characters for indentations.

#### Comments

- We use two styles for comments: documentation, and non-documentation comments
- Documentation comments are for documenting the code (and for
  IntelliSense). All these comments will be stored in XML files for
  IntelliSense.
- Documentation comments start with triple slashes: ```/// Your comment.```
- Documentation comments should be above the code
- Non-documentation comments are ordinary comments
- Non-documentation comments are put in between ```(*``` and ```*)```

#### Naming

- We use nouns for variables (or parameters).
- We *mostly* use verbs for function names.

### Line-endings

We always use unix-style (LF) line-endings for every file.

#### Editor Settings

- See our [.editorconfig](.editorconfig)

- For Emacs users:
    ```
    (setq-default fsharp-indent-offset 2)
    ```

- For Vim users:
    ```
    autocmd FileType fsharp setlocal softtabstop=2
    autocmd FileType fsharp setlocal shiftwidth=2
    autocmd FileType fsharp setlocal textwidth=80
    ```

#### Specific Rules

##### Argument Assignments

When using the equality operator (=):
```fsharp
let func = value  // Good
if foo = bar then // Good

let func=value  // Bad
if foo=bar then // Bad
```

When using (=) for argument assignments:
```fsharp
Func(param = argu)         // Good
| Func(pattern = bound)    // Good
let func (param = bound) = // Good

Func(param=argu)         // Bad
| Func(pattern= bound)   // Bad
let func (param =bound) = // Bad
```

##### Tuple Constructs

When writing tuples, use consistent spacing between elements.
Do not omit spaces or add inconsistent spacing.
```fsharp
1, 2, 3  // Good
1,2,3    // Bad
1,  2, 3 // Bad
```

##### Parentheses Constructs

When writing parentheses, apply clean formatting without unnecessary spaces.
```fsharp
()           // Good
( )          // Bad
(elements)   // Good
( elements ) // Bad
```

##### List/Array Literals

We prefer to have space chars for list/array literals. For example,
```fsharp
[ 1; 2; 3 ] // Good
[1; 2; 3]   // Bad
```

For arrays, the same spacing rules apply:
```fsharp
[| 1; 2; 3 |] // Good
[|1; 2; 3|]   // Bad
```

When we use a range operator:
```fsharp
[ 1 .. 10 ] // Good
[1 .. 10]   // Bad
[ 1..10 ]   // Bad
```

Element spacing must be exactly one space after semicolons:
```fsharp
[ 1; 2; 3 ]  // Good
[ 1;2; 3 ]   // Bad
[ 1;  2; 3 ] // Bad
```

When there is no element:
```fsharp
[]  // Good
[ ] // Bad
```

For nested literals, outer containers have internal spacing:
```fsharp
[ [ 1; 2 ]; [ 3; 4 ] ] // Good
[[ 1; 2 ]; [ 3; 4 ]]   // Bad
```

For multiline literals, prefer single-line unless exceeding 80 characters:
```fsharp
let good = [ elements ]
```

When multiline format is required, use only this structure:
```fsharp
let good =
  [ element
    element ]
```

When pattern matching on a list:
```fsharp
match lst with
| e1 :: [] -> ...
| e1 :: e2 :: [] -> ...
```

##### Indexed Property

When using indexed property, we prefer bracket notation for accessing elements:
```fsharp
src[0] <- Const      // Good
src[ 0 ] <- Const    // Bad
src.Item(0) <- Const // Bad
```

For array/list indexing and slicing, we do not use spaces inside brackets:
```fsharp
src[1]        // Good
src[1..3]     // Good
src[1..]      // Good
src[..3]      // Good
src[1..2..10] // Good

src[ 1 ]            // Bad
src[ 1 .. 3 ]       // Bad
src[ 1 .. ]         // Bad
src[ .. 3 ]         // Bad
src[ 1 .. 2 .. 10 ] // Bad
```

##### Type Annotation

We prefer to have a space character between a colon and a type name. For
example,
```fsharp
let fn (p: int) = ... // Good
let fn (p:int) = ...  // Bad
```

##### Generic Type Argument

When writing generic type arguments, do not include spaces between brackets
```fsharp
func<type>   // Good
func< type > // Bad
```

When using tuple types inside generic type arguments, use it as shown below.
```fsharp
func<type1, type2>  // Good
func<type1 * type2> // Good

func<type1,type2> // Bad
func<type1*type2> // Bad
```

When generic type arguments are followed by parentheses, use it as shown below.
```fsharp
Func<'T>()                // Good
List<int>()               // Good
Dictionary<string, int>() // Good

Func<'T> ()                // Bad
List<int> ()               // Bad
Dictionary<string, int> () // Bad
```

##### Records

We define a record as follows.
```fsharp
type InsSize =
  { MemSize: MemorySize
    RegSize: RegType
    OperationSize: RegType
    SizeCond: OperandsSizeCondition } // Good

type InsSize =
{
  MemSize: MemorySize
  RegSize: RegType
  OperationSize:   RegType        // Bad
  SizeCond: OperandsSizeCondition // Bad
}

{ Prefixes = prefs } // Good
{Prefixes = prefs}   // Bad

{ Prefixes = prefs
  Opcode = opcode } // Good
{
  Prefixes = prefs
  Opcode = opcode
}                   // Bad

{ Prefixes = prefs } // Good
{ Prefixes= prefs }  // Bad

{ Prefixes = prefs; Opcode = opcode } // Good
{ Prefixes = prefs;Opcode = opcode }  // Bad
```

##### Function Body

Avoid using an empty newline in the function body. People often use an empty
newline in the function body to separate logical blocks. One may think that this
is better for readability, but using an empty newline in the function body
implies that the function is already too long. You should instead refactor the
function into smaller functions.
```fsharp
let fn p =
  let x = foo p
  let y = foo p
  let z = x + y // Good

let fn p =
  (* omitted complex logic *)
  let x = (* something *)
  (* omitted complex logic *)
  let y = (* something *)

  let z = x + y // Bad
```

When defining mutual recursive functions, place exactly one empty newline
between let rec and and declarations.
```fsharp
let rec isEven n =
  if n = 0 then true
  else isOdd (n - 1)

and isOdd n =
  if n = 0 then false
  else isEven (n - 1) // Good

let rec isEven n =
  if n = 0 then true
  else isOdd (n - 1)
and isOdd n =
  if n = 0 then false
  else isEven (n - 1) // Bad

let nested () =
  let rec isEven n =
    if n = 0 then true
    else isOdd (n - 1)

  and isOdd n =
    if n = 0 then false
    else isEven (n - 1)

  isEven 10 // Bad
```

##### Declarations

For top-level bindings, separate them with exactly one empty line:
```fsharp
let foo = 1

let bar = 2 // Good

let foo = 1
let bar = 2 // Bad

let foo = 1


let bar = 2 // Bad
```

##### Function Calls

When calling a non-curried function, we use the following style:
```fsharp
Func(p1, p2, p3)  // Good
Func (p1, p2, p3) // Bad
```

When the method name starts with an uppercase, write it without a space
after the dot to support chain calls. When it starts with a lowercase,
add a space to follow curried function style.
```fsharp
String.Replace()  // Good
String.replace () // Good
String.Replace () // Bad
String.replace()  // Bad
```

Someone may say that it is covenient to not use any space character between the
function name and the parameters, especially when the function is not F#-style
(curried) functions. For example, it allows us to chain multiple member calls as
below.
```fsharp
str.Replace("A", "B").Replace("C", "D") // It is easy to chain calls.
```
However, we still do not recommend this style because this is more suited for
OOP languages such as C#, but not for F#. We still *allow* this style when you
call a chain of member functions though.

##### Pattern Matching Constructs

There must be exactly one space between the match expression and the with keyword.

```fsharp
match x with   // Good
| Foo -> Some good
| Bar -> None

match   x with // Bad
| Foo -> Some bad
| Bar -> None
```

The match and with keywords must be on the same line.

```fsharp
match x with // Good
| Foo -> Some good
| Bar -> None

match x      // Bad
with
| Foo -> Some bad
| Bar -> None
```

The pipe (|) and the pattern must be on the same line.

```fsharp
match x with // Good
| Foo -> Some good
| Bar -> None

match x with // Good
| Foo | Bar -> Some good

match x with // Bad
| Foo |
  Bar -> Some bad
```

Each pipe (|) must be aligned vertically with the match keyword.

```fsharp
match x with // Good
| Foo -> Some good
| Bar -> None

match x with // Bad
  | Foo -> Some bad
  | Bar -> None
```

There must be a space after the pipe (|).

```fsharp
match x with // Good
| Foo -> Some good
| Bar -> None

match x with // Bad
|Foo -> Some bad
|Bar -> None
```

When there are elements on both sides of '->', spaces are required on the side with elements.

```fsharp
match x with // Good
| Foo -> Some good
| Bar -> None

match x with // Bad
| Foo-> Some bad
| Bar ->None
```

##### Class and Member Definition

We prefer to define classes with a space character
between the name and the parentheses.
```fsharp
type Class() =  // Good
type Class () = // Bad
```

For classes with access modifiers, the access modifier should be placed directly
before the parentheses without a space.
```fsharp
type GenericClass<'T> private() =  // Good
type GenericClass<'T> private () = // Bad
```

When defining auxiliary constructors using new, we use the following style.
```fsharp
new(value) = Class(value)  // Good
new (value) = Class(value) // Bad
```

When defining properties using `with`, we use the following style.
```fsharp
member _.Method with get() = value and set(value) = value   // Good
member _.Method with get () = value and set (value) = value // Bad
```

When function name is LowerCase, use a space before parentheses.
and function name is PascalCase, attach the parentheses to the function name.
```fsharp
member _.Method() = value       // Good
static member Method() = value  // Good
static member method () = value // Good

member _.Method () = value      // Bad
static member Method () = value // Bad
static member method() = value  // Bad
```

Member functions should always use non-curried style with parentheses
when there are multiple parameters. Single parameters can omit parentheses.
```fsharp
member _.Add(x, y) = x + y                 // Good
member _.Square(x) = x * x                 // Good
static member Create(value) = Calculator() // Good
static member Create value = Calculator()  // Good

member _.Add x y = x + y    // Bad
member _.Square (x) = x * x // Bad
```

We use `this` for a self-identifier when we need to use it. However, for other
cases, we use a single underscore `_` to consistently indicate that we do not
need to use it. We avoid using `__` for a self-identifier because it is less
readable.

```fsharp
type Class() =
  member this.A(p1, p2) = this.Foo p1 // Good
  member _.A(p1, p2) = Foo p1         // Good

type Class() =
  member this.A(p1, p2) = Foo p1  // Bad
  member __.A(p1, p2) = __.Foo p1 // Bad
```

### JavaScript & CSS Coding Style

We use camlCase for JavaScript, and BEM (Block, Element, and Modifier) for CSS.
Specifically, we follow styles suggested from
https://www.w3schools.com/js/js_conventions.asp and http://getbem.com/naming/.
Additionally, we use `js-` prefix for IDs of DOM objects, when they are used in
JavaScript.
