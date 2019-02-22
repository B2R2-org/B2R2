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

Please read the [F# design
guidelines](https://fsharp.org/specs/component-design-guidelines/) and the [F#
style
guideline](https://github.com/fsprojects/fantomas/blob/master/docs/FormattingConventions.md),
before you proceed as we mostly follow these guidelines.

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

#### Editor Settings

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

##### List Literals

We prefer to have space chars for list literals. For example,
```fsharp
[ 1; 2; 3 ] // Good
[1; 2; 3]   // Not good
```

When we use a range operator:
```fsharp
[ 1 .. 10 ] // Good
[1 .. 10]   // Not good
[ 1..10 ]   // Not good
```

When there is no element:
```fsharp
[]   // Good
[ ]  // Not good
```

When pattern matching on a list:
```fsharp
match lst with
| e1 :: [] -> ...
| e1 :: e2 :: [] -> ...
```

##### Type Annotation

We prefer to have a space character between a colon and a type name. For
example,
```fsharp
let fn (p: int) = ... // Good
let fn (p:int) = ...  // Not good
```

##### Records

We define a record as follows.
```fsharp
type InsSize = {  // Good
  MemSize       : MemorySize
  RegSize       : RegType
  OperationSize : RegType
  SizeCond      : OperandsSizeCondition
}
type InsSize =    // Not good
{
  MemSize       : MemorySize
  RegSize       : RegType
  OperationSize : RegType
  SizeCond      : OperandsSizeCondition
}

{ Prefixes = prefs } // Good
{Prefixes = prefs}   // Not good

{ Prefixes = prefs
  Opcode = opcode } // Good
{
  Prefixes = prefs
  Opcode = opcode
}                   // Not good
```

##### Function Calls

When calling a non-curried function, we use the following style:
```fsharp
Func (p1, p2, p3)   // Good
Func(p1, p2, p3)    // Okay, but not recommended.
Func ( p1, p2, p3 ) // Not good
Func( p1, p2, p3 )  // Not good
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

```fsharp
match x with
| Foo ->
  Some good
| Bar ->
  None         // Good

match x with
| Foo ->
    Some good
| Bar ->
    None       // Bad
```

##### Class and Member Definition

We prefer to define classes and member functions in a more F#-like way.

```fsharp
type Class () =
  member A (p1, p2) = // Good

type Class() = // Bad
  member A(p1, p2) = // Bad
```
