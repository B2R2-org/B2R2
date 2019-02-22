@ECHO OFF

SET TARGET=%1
IF "%TARGET%" == "" CALL :TARGETdefault
IF "%TARGET%" == "all" CALL :TARGETdefault
IF "%TARGET%" == "build" CALL :TARGETdefault
IF "%TARGET%" == "clean" CALL :TARGETclean
IF "%TARGET%" == "release" CALL :TARGETrelease
IF "%TARGET%" == "test" CALL :TARGETtest
IF "%TARGET%" == "publish" CALL :TARGETpublish
EXIT /B

:TARGETdefault
    dotnet build /p:DefineConstants=DEBUG
    GOTO TARGETend

:TARGETrelease
    dotnet build -c Release
    GOTO TARGETend

:TARGETtest
    dotnet test
    GOTO TARGETend

:TARGETpublish
    rmdir /S /Q build
    dotnet publish -c Release -o %CD%\build\
    GOTO TARGETend

:TARGETclean
    dotnet clean -c Debug
    dotnet clean -c Release
    GOTO TARGETend

:TARGETend
    GOTO :EOF
