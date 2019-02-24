# B2R2 APIs

This page describes several B2R2 modules. Our API documentation still needs a
lot of love: we are waiting for your PRs :smile:.

## B2R2 Namespace

`B2R2` is the top-level namespace. It includes various modules and types for
binary analysis.

## B2R2.BinFile Namespace

`B2R2.BinFile` is the namespace for various types and functions for parsing and
manipulating binary files.

## B2R2.BinGraph Namespace

`B2R2.BinGraph` is the namespace that provides an abstractiton layer for graph
algorithms, such as CFG construction algorithm, dominance algorithm, and etc.

## B2R2.BinGraph Namespace

`B2R2.BinIR` is the namespace for our Intermediate Representations (IRs). For
example, `B2R2.BinIR.LowUIR` contains our machine-level IR, called LowUIR, which
can be directly lifted from machine code.

## B2R2.FrontEnd Namespace

`B2R2.FrontEnd` is the namespace for our front-end modules. A front-end in B2R2
involves three main tasks: (1) parsing binary code, (2) lifting the parsed code
into LowUIR statements, and (3) performing several optimizations on the LowIR
statements.
