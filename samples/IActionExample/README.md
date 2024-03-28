# MyAction example

To build a plugin DLL file for Transformer, follow the steps below.

1. Copy `MyAction.fs.example` to `MyAction.fs`.
2. Modify `MyAction.fs` as you want.
3. Run `dotnet build` or `dotnet build -c Release` to get `MyAction.dll`, which
   should be located at `bin/Debug` or `bin/Release` directory.
4. Run transformer using the `-d` option with the dll you just created.
