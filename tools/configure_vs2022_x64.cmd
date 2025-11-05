@echo off
setlocal

set CMAKE_EXE=C:\Program Files\CMake\bin\cmake.exe

if not exist "%CMAKE_EXE%" (
  echo [ERROR] CMake not found at %CMAKE_EXE%
  echo If you just installed via winget, wait for install to finish or open a new terminal.
  echo Alternatively, adjust the path in .vscode/settings.json ^(cmake.cmakePath^).
  exit /b 1
)

echo [INFO] Using CMake at "%CMAKE_EXE%"
echo [STEP] Configure VS 2022 x64 generator...
"%CMAKE_EXE%" -S "%CD%" -B "build\vs2022-x64" -G "Visual Studio 17 2022" -A x64
set "ERR=%ERRORLEVEL%"
if not "%ERR%"=="0" (
  echo [ERROR] CMake configure failed with code %ERR%.
  exit /b %ERR%
)

echo [OK] Configure completed. Solution is at build\vs2022-x64\
exit /b 0
